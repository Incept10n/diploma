package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CronController struct {
	clientset  *kubernetes.Clientset
	config     *SecurityConfig
	restConfig *rest.Config
}

func NewCronController(clientset *kubernetes.Clientset, config *SecurityConfig) *CronController {
	return &CronController{
		clientset: clientset,
		config:    config,
	}
}

func (c *CronController) StartMonitoring(ctx context.Context) {
	ticker := time.NewTicker(c.config.Cron.MonitoringInterval)
	defer ticker.Stop()

	// Первый запуск сразу
	c.checkAllPods()

	for {
		select {
		case <-ticker.C:
			c.checkAllPods()
		case <-ctx.Done():
			log.Println("Cron monitoring stopped")
			return
		}
	}
}

func (c *CronController) checkAllPods() {
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
	// Проверяем наличие подозрительных cron-задач через exec
	suspiciousCrons, err := c.findSuspiciousCronJobs(pod, container)
	if err != nil {
		log.Printf("Error checking cron jobs in pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return
	}

	if len(suspiciousCrons) > 0 {
		c.handleSuspiciousCronJobs(pod, container, suspiciousCrons)
	}
}

func (c *CronController) findSuspiciousCronJobs(pod *v1.Pod, container *v1.Container) ([]string, error) {
	var suspiciousJobs []string

	// Проверяем основные пути cron
	for _, path := range c.config.Cron.MonitoredPaths {
		content, err := c.readFileFromContainer(pod, container, path)
		if err != nil {
			// Файл может не существовать, это нормально
			continue
		}

		// Анализируем содержимое на подозрительные паттерны
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if c.isSuspiciousCronJob(line) && !c.isAllowedCommand(line) {
				suspiciousJobs = append(suspiciousJobs, fmt.Sprintf("Path: %s, Job: %s", path, line))
			}
		}
	}

	return suspiciousJobs, nil
}

func (c *CronController) isSuspiciousCronJob(jobLine string) bool {
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
	// Это можно улучшить для более точного анализа
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
	// Для простоты возвращаем пустую строку
	// Позже реализуем реальное чтение файлов из контейнеров
	// через exec или другие методы
	return "", fmt.Errorf("not implemented")
}

func (c *CronController) handleSuspiciousCronJobs(pod *v1.Pod, container *v1.Container, jobs []string) {
	log.Printf("⚠️  SUSPICIOUS CRON JOBS DETECTED in pod %s/%s, container %s:",
		pod.Namespace, pod.Name, container.Name)

	for _, job := range jobs {
		log.Printf("  - %s", job)
	}

	// Здесь можно добавить автоматическое реагирование:
	// - Отправка уведомлений
	// - Блокировка задач
	// - Изоляция пода
	// - Создание инцидента безопасности
}

// Метод для добавления разрешенных команд в runtime
func (c *CronController) AddAllowedCommand(command string) {
	// Проверяем, что команда еще не в списке
	for _, existing := range c.config.Cron.AllowedCommands {
		if existing == command {
			return
		}
	}
	c.config.Cron.AllowedCommands = append(c.config.Cron.AllowedCommands, command)
	log.Printf("Added allowed command: %s", command)
}

// Метод для добавления подозрительных паттернов
func (c *CronController) AddSuspiciousPattern(pattern string) {
	c.config.Cron.SuspiciousPatterns = append(c.config.Cron.SuspiciousPatterns, pattern)
	log.Printf("Added suspicious pattern: %s", pattern)
}
