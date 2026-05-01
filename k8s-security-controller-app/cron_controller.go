package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type CronController struct {
	clientset  *kubernetes.Clientset
	restConfig *rest.Config
	config     *SecurityConfig
	mu         sync.RWMutex
}

func NewCronController(clientset *kubernetes.Clientset, restConfig *rest.Config, config *SecurityConfig) *CronController {
	return &CronController{
		clientset:  clientset,
		restConfig: restConfig,
		config:     config,
	}
}

func (c *CronController) checkAllPods() {
	c.mu.RLock()
	if !c.config.Cron.Enabled {
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()

	log.Println("Starting cron check for all pods...")

	pods, err := c.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Error listing pods: %v", err)
		return
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase == v1.PodRunning {
			c.checkPodForCronJobs(&pod)
		}
	}

	log.Println("Cron check completed")
}

func (c *CronController) checkPodForCronJobs(pod *v1.Pod) {
	for _, container := range pod.Spec.Containers {
		c.checkContainerForCron(pod, &container)
	}
}

func (c *CronController) checkContainerForCron(pod *v1.Pod, container *v1.Container) {
	suspiciousCrons, err := c.findSuspiciousCronJobs(pod, container)
	if err != nil {
		log.Printf("Error checking cron jobs in pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return
	}

	if len(suspiciousCrons) > 0 {
		c.handleSuspiciousCronJobs(pod, container, suspiciousCrons)
	} else {
		log.Println("No suspicious crons detected")
	}
}

func (c *CronController) findSuspiciousCronJobs(pod *v1.Pod, container *v1.Container) ([]SuspiciousCronJob, error) {
	log.Println("Checking for suspicious crons")

	var suspiciousJobs []SuspiciousCronJob

	for _, path := range c.config.Cron.MonitoredPaths {

		cmdToListFiles := []string{"/bin/sh", "-c", "ls -1 " + path + " | xargs realpath"}
		files, _ := c.executeCommandInContainer(pod, container, cmdToListFiles)
		linesFromStdout := strings.Split(files, "\n")

		for _, file := range linesFromStdout {

			content, err := c.readFileFromContainer(pod, container, file)

			if err != nil {
				continue
			}

			lines := strings.Split(content, "\n")
			for lineNum, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				if c.isSuspiciousCronJob(line) && !c.isAllowedCommand(line) {
					suspiciousJobs = append(suspiciousJobs, SuspiciousCronJob{
						Path:     file,
						Line:     line,
						LineNum:  lineNum + 1,
						FullPath: fmt.Sprintf("%s:%d", file, lineNum+1),
					})
				}
			}

		}

	}

	return suspiciousJobs, nil
}

type SuspiciousCronJob struct {
	Path     string
	Line     string
	LineNum  int
	FullPath string
}

func (c *CronController) isSuspiciousCronJob(jobLine string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, pattern := range c.config.Cron.SuspiciousPatterns {
		if strings.Contains(jobLine, pattern) {
			return true
		}
	}

	if c.isTooFrequent(jobLine) {
		return true
	}

	return false
}

func (c *CronController) isTooFrequent(jobLine string) bool {
	frequentPatterns := []string{
		"* * * * *",
		"*/1 *",
		"* * * * * *",
	}

	for _, pattern := range frequentPatterns {
		if strings.Contains(jobLine, pattern) {
			return true
		}
	}

	return false
}

func (c *CronController) isAllowedCommand(jobLine string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, allowed := range c.config.Cron.AllowedCommands {
		if strings.Contains(jobLine, allowed) {
			if !c.isMaliciousUsage(jobLine, allowed) {
				return true
			}
		}
	}
	return false
}

func (c *CronController) isMaliciousUsage(jobLine, allowedCommand string) bool {
	maliciousIndicators := []string{
		"&&", "||", ";", "|", "`", "$(",
		"wget", "curl", "nc", "ncat",
		"/tmp/", "/dev/shm/",
	}

	for _, indicator := range maliciousIndicators {
		if strings.Contains(jobLine, indicator) {
			return true
		}
	}

	return false
}

func (c *CronController) readFileFromContainer(pod *v1.Pod, container *v1.Container, filePath string) (string, error) {
	cmd := []string{"/bin/sh", "-c", "cat " + filePath}
	return c.executeCommandInContainer(pod, container, cmd)
}

func (c *CronController) executeCommandInContainer(pod *v1.Pod, container *v1.Container, command []string) (string, error) {
	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Container: container.Name,
			Command:   command,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.restConfig, "POST", req.URL())
	if err != nil {
		log.Printf("Error creating executor: %s", err.Error())
		return "", err
	}

	var stdout, stderr strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})

	if err != nil {
		return "", fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}

	log.Printf("Command executed successfully. Output length: %d bytes", stdout.Len())

	return stdout.String(), nil
}

func (c *CronController) handleSuspiciousCronJobs(pod *v1.Pod, container *v1.Container, jobs []SuspiciousCronJob) {
	log.Printf("⚠️  SUSPICIOUS CRON JOBS DETECTED in pod %s/%s, container %s:",
		pod.Namespace, pod.Name, container.Name)

	for _, job := range jobs {
		log.Printf("  - %s: %s", job.FullPath, job.Line)
	}

	c.removeSuspiciousCronJobs(pod, container, jobs)
}

func (c *CronController) removeSuspiciousCronJobs(pod *v1.Pod, container *v1.Container, jobs []SuspiciousCronJob) {
	log.Printf("🔧 Attempting to remove suspicious cron jobs from pod %s/%s", pod.Namespace, pod.Name)

	for _, job := range jobs {
		if err := c.removeLineFromFile(pod, container, job.Path, job.LineNum); err != nil {
			log.Printf("❌ Failed to remove cron job from %s: %v", job.FullPath, err)
		} else {
			log.Printf("✅ Successfully removed suspicious cron job: %s", job.Line)

			c.sendRemediationNotification(pod, container, job)
		}
	}
}

func (c *CronController) removeLineFromFile(pod *v1.Pod, container *v1.Container, filePath string, lineNum int) error {
	content, err := c.readFileFromContainer(pod, container, filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	lines := strings.Split(content, "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		lines = append(lines[:lineNum-1], lines[lineNum:]...)

		newContent := strings.Join(lines, "\n")
		return c.writeFileToContainer(pod, container, filePath, newContent)
	}

	return fmt.Errorf("line number %d out of range", lineNum)
}

func (c *CronController) writeFileToContainer(pod *v1.Pod, container *v1.Container, filePath, content string) error {
	cmd := []string{"sh", "-c", fmt.Sprintf("echo '%s' > %s", content, filePath)}

	_, err := c.executeCommandInContainer(pod, container, cmd)
	return err
}

func (c *CronController) sendRemediationNotification(pod *v1.Pod, container *v1.Container, job SuspiciousCronJob) {
	log.Printf("📢 Remediation notification: Removed suspicious cron job from %s/%s: %s",
		pod.Namespace, pod.Name, job.Line)
}

func (c *CronController) AddAllowedCommand(command string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, existing := range c.config.Cron.AllowedCommands {
		if existing == command {
			log.Printf("Command %s already in allowed list", command)
			return
		}
	}
	c.config.Cron.AllowedCommands = append(c.config.Cron.AllowedCommands, command)
	log.Printf("✅ Added allowed command: %s", command)
}

func (c *CronController) GetConfig() *SecurityConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *CronController) StartAgentMonitoring(ctx context.Context, nodeName string) {

	ticker := time.NewTicker(c.config.Cron.MonitoringInterval)
	defer ticker.Stop()

	log.Printf("Agent mode: monitoring pods on node %s", nodeName)

	for {
		select {
		case <-ticker.C:
			c.checkPodsOnNode(nodeName)
		case <-ctx.Done():
			log.Println("Agent monitoring stopped")
			return
		}
	}
}

func (c *CronController) checkPodsOnNode(nodeName string) {
	c.mu.RLock()
	if !c.config.Cron.Enabled {
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()

	log.Printf("Agent checking cron jobs on node %s...", nodeName)

	pods, err := c.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		log.Printf("Error listing pods on node %s: %v", nodeName, err)
		return
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase == v1.PodRunning {
			c.checkPodForCronJobs(&pod)
		}
	}

	log.Printf("Agent cron check on node %s completed", nodeName)
}
