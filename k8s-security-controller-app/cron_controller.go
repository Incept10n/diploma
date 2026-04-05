package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
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
	// Проверяем каждый контейнер в поде
	for _, container := range pod.Spec.Containers {
		c.checkContainerForCron(pod, &container)
	}
}

func (c *CronController) checkContainerForCron(pod *v1.Pod, container *v1.Container) {
	// Проверяем наличие подозрительных cron-задач
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

	// Проверяем основные пути cron
	for _, path := range c.config.Cron.MonitoredPaths {

		cmdToListFiles := []string{"/bin/sh", "-c", "ls -1 " + path + " | xargs realpath"}
		files, _ := c.executeCommandInContainer(pod, container, cmdToListFiles)
		linesFromStdout := strings.Split(files, "\n")

		for _, file := range linesFromStdout {

			content, err := c.readFileFromContainer(pod, container, file)

			if err != nil {
				// Файл может не существовать, это нормально
				continue
			}

			// Анализируем содержимое на подозрительные паттерны
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

	// Проверка на слишком частое выполнение
	if c.isTooFrequent(jobLine) {
		return true
	}

	return false
}

func (c *CronController) isTooFrequent(jobLine string) bool {
	// Простая проверка на частоту выполнения
	frequentPatterns := []string{
		"* * * * *",   // каждую минуту
		"*/1 *",       // каждую минуту
		"* * * * * *", // каждую секунду (если поддерживается)
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

	// Проверяем, содержит ли задача разрешенные команды
	for _, allowed := range c.config.Cron.AllowedCommands {
		if strings.Contains(jobLine, allowed) {
			// Дополнительная проверка: если команда разрешена,
			// убедимся, что она не используется вредоносно
			if !c.isMaliciousUsage(jobLine, allowed) {
				return true
			}
		}
	}
	return false
}

func (c *CronController) isMaliciousUsage(jobLine, allowedCommand string) bool {
	// Проверяем, не используется ли разрешенная команда вредоносно
	maliciousIndicators := []string{
		"&&", "||", ";", "|", "`", "$(", // командные операторы
		"wget", "curl", "nc", "ncat", // подозрительные команды
		"/tmp/", "/dev/shm/", // подозрительные пути
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
	defer cancel() // Важно: предотвращает утечку ресурсов

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

	// Автоматическое реагирование: удаляем подозрительные задачи
	c.removeSuspiciousCronJobs(pod, container, jobs)
}

func (c *CronController) removeSuspiciousCronJobs(pod *v1.Pod, container *v1.Container, jobs []SuspiciousCronJob) {
	log.Printf("🔧 Attempting to remove suspicious cron jobs from pod %s/%s", pod.Namespace, pod.Name)

	for _, job := range jobs {
		// Для каждого файла с подозрительными задачами
		if err := c.removeLineFromFile(pod, container, job.Path, job.LineNum); err != nil {
			log.Printf("❌ Failed to remove cron job from %s: %v", job.FullPath, err)
		} else {
			log.Printf("✅ Successfully removed suspicious cron job: %s", job.Line)

			// Отправляем уведомление об удалении
			c.sendRemediationNotification(pod, container, job)
		}
	}
}

func (c *CronController) removeLineFromFile(pod *v1.Pod, container *v1.Container, filePath string, lineNum int) error {
	// Читаем файл
	content, err := c.readFileFromContainer(pod, container, filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Разбиваем на строки и удаляем нужную строку
	lines := strings.Split(content, "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		// Удаляем строку (нумерация с 1, а индексация с 0)
		lines = append(lines[:lineNum-1], lines[lineNum:]...)

		// Записываем обновленное содержимое обратно
		newContent := strings.Join(lines, "\n")
		return c.writeFileToContainer(pod, container, filePath, newContent)
	}

	return fmt.Errorf("line number %d out of range", lineNum)
}

func (c *CronController) writeFileToContainer(pod *v1.Pod, container *v1.Container, filePath, content string) error {
	// Создаем команду для записи в файл
	cmd := []string{"sh", "-c", fmt.Sprintf("echo '%s' > %s", content, filePath)}

	_, err := c.executeCommandInContainer(pod, container, cmd)
	return err
}

func (c *CronController) sendRemediationNotification(pod *v1.Pod, container *v1.Container, job SuspiciousCronJob) {
	// Здесь можно реализовать отправку уведомлений (Slack, Email, etc.)
	log.Printf("📢 Remediation notification: Removed suspicious cron job from %s/%s: %s",
		pod.Namespace, pod.Name, job.Line)
}

// Метод для добавления разрешенных команд в runtime
func (c *CronController) AddAllowedCommand(command string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Проверяем, что команда еще не в списке
	for _, existing := range c.config.Cron.AllowedCommands {
		if existing == command {
			log.Printf("Command %s already in allowed list", command)
			return
		}
	}
	c.config.Cron.AllowedCommands = append(c.config.Cron.AllowedCommands, command)
	log.Printf("✅ Added allowed command: %s", command)
}

// Метод для добавления подозрительных паттернов
func (c *CronController) AddSuspiciousPattern(pattern string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config.Cron.SuspiciousPatterns = append(c.config.Cron.SuspiciousPatterns, pattern)
	log.Printf("✅ Added suspicious pattern: %s", pattern)
}

// Метод для получения текущей конфигурации
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

// Контроллер работает как управляющий сервис (только API)
func (c *CronController) StartControllerService(ctx context.Context) {
	// Запускаем HTTP сервер для API
	go startHTTPServer()

	log.Println("Controller mode: running as management service")
	log.Println("API server started on :8080")

	// Ждем сигнала завершения
	<-ctx.Done()
	log.Println("Controller service stopped")
}

// Агент проверяет только поды на своей ноде
func (c *CronController) checkPodsOnNode(nodeName string) {
	c.mu.RLock()
	if !c.config.Cron.Enabled {
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()

	log.Printf("Agent checking cron jobs on node %s...", nodeName)

	// Фильтруем поды только на этой ноде
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

// HTTP сервер для контроллера
func startHTTPServer() {
	http.HandleFunc("/api/allowed-commands", handleAllowedCommands)
	http.HandleFunc("/api/suspicious-patterns", handleSuspiciousPatterns)
	http.HandleFunc("/api/config", handleConfig)

	log.Println("Starting HTTP server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
