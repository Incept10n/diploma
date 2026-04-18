package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
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

type FileMonitor struct {
	clientset    *kubernetes.Clientset
	restConfig   *rest.Config
	config       *SecurityConfig
	mu           sync.RWMutex
	baseline     map[string]map[string]FileState // baseline состояние файлов при старте
	currentState map[string]map[string]FileState // текущее состояние файлов
	startTime    time.Time                       // Время старта агента
}

type FileState struct {
	ModTime   time.Time
	Size      int64
	IsDir     bool
	FirstSeen time.Time // когда файл был впервые замечен агентом
}

type SuspiciousFile struct {
	Path      string
	Reason    string
	Size      int64
	ModTime   time.Time
	FirstSeen time.Time
}

type SuspiciousAccess struct {
	FilePath  string
	Process   string
	Reason    string
	Timestamp time.Time
}

type ProcessInfo struct {
	PID     string
	Command string
	User    string
	Args    []string
}

func NewFileMonitor(clientset *kubernetes.Clientset, restConfig *rest.Config, config *SecurityConfig) *FileMonitor {
	fm := &FileMonitor{
		clientset:    clientset,
		restConfig:   restConfig,
		config:       config,
		baseline:     make(map[string]map[string]FileState),
		currentState: make(map[string]map[string]FileState),
	}

	return fm
}

func (fm *FileMonitor) StartAgentMonitoring(ctx context.Context, nodeName string) {
	// Начальное время
	fm.startTime = time.Now()
	log.Printf("File monitor agent started at: %s", fm.startTime.Format("2006-01-02 15:04:05"))

	ticker := time.NewTicker(fm.config.FileMonitoring.MonitoringInterval)
	defer ticker.Stop()

	log.Printf("File monitor agent mode: monitoring pods on node %s", nodeName)

	for {
		select {
		case <-ticker.C:
			fm.startTime = time.Now()
			log.Printf("Starting file check at: %s", fm.startTime.Format("2006-01-02 15:04:05"))
			fm.checkPodsOnNode(nodeName)
		case <-ctx.Done():
			log.Println("File monitor agent stopped")
			return
		}
	}
}

func (fm *FileMonitor) checkPodsOnNode(nodeName string) {
	fm.mu.RLock()
	if !fm.config.FileMonitoring.Enabled {
		fm.mu.RUnlock()
		return
	}
	fm.mu.RUnlock()

	log.Printf("File monitor checking pods on node %s...", nodeName)

	// Фильтруем поды только на этой ноде
	pods, err := fm.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		log.Printf("Error listing pods on node %s: %v", nodeName, err)
		return
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase == v1.PodRunning {
			fm.checkPodFiles(&pod)
		}
	}

	log.Printf("File monitor check on node %s completed", nodeName)
}

func (fm *FileMonitor) checkPodFiles(pod *v1.Pod) {
	// Проверяем каждый контейнер в поде
	for _, container := range pod.Spec.Containers {
		fm.checkContainerFiles(pod, &container)
		fm.checkSecretsAccess(pod, &container)
	}
}

func (fm *FileMonitor) checkContainerFiles(pod *v1.Pod, container *v1.Container) {
	// Собираем текущее состояние файлов
	fm.collectCurrentState(pod, container)

	// Проверяем новые файлы
	fm.checkNewFiles(pod, container)

	// Проверяем запрещенные расширения
	fm.checkForbiddenExtensions(pod, container)
}

// Сбор текущего состояния файлов
// Сбор текущего состояния файлов
func (fm *FileMonitor) collectCurrentState(pod *v1.Pod, container *v1.Container) {
	podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Инициализируем мапу если нужно
	if fm.currentState[podName] == nil {
		fm.currentState[podName] = make(map[string]FileState)
	}

	currentFiles := fm.currentState[podName]

	// Проверяем все директории в protected paths
	for _, protectedPath := range fm.config.FileMonitoring.ProtectedPaths {
		files, err := fm.listFilesInDirectory(pod, container, protectedPath)
		if err != nil {
			log.Printf("Error listing files in %s: %v", protectedPath, err)
			continue
		}

		for _, file := range files {
			filePath := file.Name

			state := FileState{
				ModTime:   file.ModTime,
				Size:      file.Size,
				IsDir:     file.IsDir,
				FirstSeen: time.Now(),
			}

			// Если файл уже существует, сохраняем FirstSeen
			if existingState, exists := currentFiles[filePath]; exists {
				state.FirstSeen = existingState.FirstSeen
			}

			currentFiles[filePath] = state
		}
	}
}

// Проверка новых файлов в защищенных директориях
// Проверка новых файлов в защищенных директориях
func (fm *FileMonitor) checkNewFiles(pod *v1.Pod, container *v1.Container) {
	podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	currentFiles, exists := fm.currentState[podName]
	if !exists {
		return
	}

	var newFiles []SuspiciousFile

	// Проверяем каждый файл в текущем состоянии
	for filePath, currentState := range currentFiles {
		// Проверяем, разрешено ли создание файлов в этой директории
		if fm.isPathAllowedForWriting(filePath) {
			continue // Эта директория разрешена для записи
		}

		// Проверяем, является ли путь защищенным
		if !fm.isPathProtected(filePath) {
			continue // Этот путь не защищен
		}

		// ✅ ГЛАВНАЯ ПРОВЕРКА: файл создан ПОСЛЕ старта агента
		if currentState.ModTime.After(fm.startTime) {
			newFiles = append(newFiles, SuspiciousFile{
				Path:      filePath,
				Reason:    fmt.Sprintf("New file created after agent start (agent started: %s)", fm.startTime.Format("2006-01-02 15:04:05")),
				Size:      currentState.Size,
				ModTime:   currentState.ModTime,
				FirstSeen: currentState.FirstSeen,
			})
		}
	}

	if len(newFiles) > 0 {
		fm.handleSuspiciousFiles(pod, container, newFiles)
	}
}

// Вспомогательные функции для управления baseline
func (fm *FileMonitor) isBaselineCollected(podName string) bool {
	// Можно хранить в отдельной мапе или проверять наличие ключа
	return len(fm.baseline[podName]) > 0
}

func (fm *FileMonitor) isFirstScan(podName string) bool {
	// Проверяем, был ли уже baseline собран
	return len(fm.baseline[podName]) == 0
}

func (fm *FileMonitor) markBaselineCollected(podName string) {
	// Можно не делать ничего, просто наличие записей в baseline - индикатор
}

// Проверка запрещенных расширений
func (fm *FileMonitor) checkForbiddenExtensions(pod *v1.Pod, container *v1.Container) {
	podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	fm.mu.RLock()
	defer fm.mu.RUnlock()

	currentFiles, exists := fm.currentState[podName]
	if !exists {
		return
	}

	var forbiddenFiles []SuspiciousFile

	for filePath, fileState := range currentFiles {
		// Проверяем расширение файла
		ext := strings.ToLower(filepath.Ext(filePath))
		log.Printf("Extension is %s", ext)

		// Если расширение запрещено
		if fm.isExtensionForbidden(ext) {
			forbiddenFiles = append(forbiddenFiles, SuspiciousFile{
				Path:      filePath,
				Reason:    fmt.Sprintf("File with forbidden extension: %s", ext),
				Size:      fileState.Size,
				ModTime:   fileState.ModTime,
				FirstSeen: fileState.FirstSeen,
			})
		}
	}

	if len(forbiddenFiles) > 0 {
		fm.handleForbiddenExtensions(pod, container, forbiddenFiles)
	}
}

// Вспомогательные функции проверки

func (fm *FileMonitor) isPathAllowedForWriting(filePath string) bool {
	for _, allowedPath := range fm.config.FileMonitoring.AllowedWritePaths {
		if strings.HasPrefix(filePath, allowedPath) {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) isPathProtected(filePath string) bool {
	for _, protectedPath := range fm.config.FileMonitoring.ProtectedPaths {
		if strings.HasPrefix(filePath, protectedPath) {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) isExtensionForbidden(ext string) bool {
	log.Println("Forbidden extensions:")
	log.Println(fm.config.FileMonitoring.ForbiddenExtensions)
	for _, forbiddenExt := range fm.config.FileMonitoring.ForbiddenExtensions {
		if strings.ToLower(forbiddenExt) == ext {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) handleSuspiciousFiles(pod *v1.Pod, container *v1.Container, files []SuspiciousFile) {
	log.Printf("⚠️  SUSPICIOUS FILES DETECTED in pod %s/%s, container %s:",
		pod.Namespace, pod.Name, container.Name)

	for _, file := range files {
		log.Printf("  - %s: %s (Size: %d, First seen: %s)",
			file.Path, file.Reason, file.Size, file.FirstSeen.Format("2006-01-02 15:04:05"))
	}

	// Автоматическое реагирование - удаление подозрительных файлов
	fm.removeSuspiciousFiles(pod, container, files)
}

func (fm *FileMonitor) handleForbiddenExtensions(pod *v1.Pod, container *v1.Container, files []SuspiciousFile) {
	log.Printf("⚠️  FORBIDDEN FILE EXTENSIONS DETECTED in pod %s/%s, container %s:",
		pod.Namespace, pod.Name, container.Name)

	for _, file := range files {
		log.Printf("  - %s: %s (Size: %d)",
			file.Path, file.Reason, file.Size)
	}

	// Автоматическое реагирование - удаление файлов с запрещенными расширениями
	fm.removeSuspiciousFiles(pod, container, files)
}

// Мониторинг доступа к секретам
func (fm *FileMonitor) checkSecretsAccess(pod *v1.Pod, container *v1.Container) {
	if !fm.config.Secrets.Enabled {
		return
	}

	// Проверяем процессы, которые могут читать секреты
	processes, err := fm.getRunningProcesses(pod, container)
	if err != nil {
		return
	}

	var suspiciousAccesses []SuspiciousAccess

	for _, process := range processes {
		// Проверяем, не читает ли процесс секреты
		for _, secretPath := range fm.config.Secrets.ProtectedPaths {
			if fm.isProcessAccessingPath(process, secretPath) {
				suspiciousAccesses = append(suspiciousAccesses, SuspiciousAccess{
					FilePath:  secretPath,
					Process:   process.Command,
					Reason:    "Process accessing protected secrets path",
					Timestamp: time.Now(),
				})
			}
		}
	}

	if len(suspiciousAccesses) > 0 {
		fm.handleSuspiciousAccess(pod, container, suspiciousAccesses)
	}
}

func (fm *FileMonitor) getRunningProcesses(pod *v1.Pod, container *v1.Container) ([]ProcessInfo, error) {
	cmd := []string{"ps", "aux", "--no-headers"}
	output, err := fm.executeCommandInContainer(pod, container, cmd)
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 11 {
			processes = append(processes, ProcessInfo{
				PID:     fields[1],
				User:    fields[0],
				Command: fields[10],
				Args:    fields[11:],
			})
		}
	}

	return processes, nil
}

func (fm *FileMonitor) isProcessAccessingPath(process ProcessInfo, path string) bool {
	// Проверяем команду и аргументы процесса
	fullCommand := process.Command + " " + strings.Join(process.Args, " ")

	for _, suspiciousPattern := range fm.config.Secrets.SuspiciousAccessPatterns {
		if strings.Contains(fullCommand, suspiciousPattern) && strings.Contains(fullCommand, path) {
			return true
		}
	}

	return false
}

func (fm *FileMonitor) handleSuspiciousAccess(pod *v1.Pod, container *v1.Container, accesses []SuspiciousAccess) {
	log.Printf("⚠️  SUSPICIOUS SECRET ACCESS DETECTED in pod %s/%s, container %s:",
		pod.Namespace, pod.Name, container.Name)

	for _, access := range accesses {
		log.Printf("  - Process '%s' accessing %s: %s",
			access.Process, access.FilePath, access.Reason)
	}

	// Автоматическое реагирование - убийство подозрительных процессов
	fm.killSuspiciousProcesses(pod, container, accesses)
}

// Вспомогательные функции для работы с файлами
type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

func (fm *FileMonitor) listFilesInDirectory(pod *v1.Pod, container *v1.Container, dirPath string) ([]FileInfo, error) {
	// Используем find для получения информации о файлах
	cmd := []string{"sh", "-c", fmt.Sprintf("/usr/bin/find %s -type f 2>/dev/null | while read f; do stat -c '%%n|%%s|%%Y' \"$f\" 2>/dev/null; done", dirPath)}

	output, _ := fm.executeCommandInContainer(pod, container, cmd)

	return fm.parseStatOutput(output), nil
}

func (fm *FileMonitor) parseStatOutput(output string) []FileInfo {
	var files []FileInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Формат: path|size|timestamp
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}

		path := parts[0]
		size := parseInt64(parts[1])
		modTimeUnix := parseInt64(parts[2])

		files = append(files, FileInfo{
			Name:    path,
			Size:    size,
			ModTime: time.Unix(modTimeUnix, 0),
			IsDir:   false,
		})
	}

	return files
}

// Вспомогательные функции
func parseInt64(s string) int64 {
	var result int64
	fmt.Sscanf(s, "%d", &result)
	return result
}

func parseUnixTime(s string) time.Time {
	timestamp := parseInt64(s)
	return time.Unix(timestamp, 0)
}

// Импортируем функцию executeCommandInContainer из cron_controller
func (fm *FileMonitor) executeCommandInContainer(pod *v1.Pod, container *v1.Container, command []string) (string, error) {
	req := fm.clientset.CoreV1().RESTClient().Post().
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

	exec, err := remotecommand.NewSPDYExecutor(fm.restConfig, "POST", req.URL())
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

	return stdout.String(), nil
}

// Удаление подозрительных файлов
func (fm *FileMonitor) removeSuspiciousFiles(pod *v1.Pod, container *v1.Container, files []SuspiciousFile) {
	log.Printf("🔧 Attempting to remove suspicious files from pod %s/%s", pod.Namespace, pod.Name)

	for _, file := range files {
		// Удаляем файл
		if err := fm.removeFile(pod, container, file.Path); err != nil {
			log.Printf("❌ Failed to remove suspicious file %s: %v", file.Path, err)
		} else {
			log.Printf("✅ Successfully removed suspicious file: %s", file.Path)

			// Отправляем уведомление об удалении
			fm.sendFileRemediationNotification(pod, container, file)
		}
	}
}

// Убийство подозрительных процессов
func (fm *FileMonitor) killSuspiciousProcesses(pod *v1.Pod, container *v1.Container, accesses []SuspiciousAccess) {
	log.Printf("🔧 Attempting to kill suspicious processes in pod %s/%s", pod.Namespace, pod.Name)

	// Получаем список всех процессов для точного определения PID
	processes, err := fm.getRunningProcesses(pod, container)
	if err != nil {
		log.Printf("❌ Failed to get process list: %v", err)
		return
	}

	for _, access := range accesses {
		// Находим PID процесса по команде
		pid := fm.findProcessPIDByCommand(processes, access.Process)
		if pid != "" {
			// Убиваем процесс
			if err := fm.killProcess(pod, container, pid); err != nil {
				log.Printf("❌ Failed to kill suspicious process %s (PID: %s): %v", access.Process, pid, err)
			} else {
				log.Printf("✅ Successfully killed suspicious process: %s (PID: %s)", access.Process, pid)

				// Отправляем уведомление об убийстве процесса
				fm.sendProcessRemediationNotification(pod, container, access, pid)
			}
		} else {
			log.Printf("❌ Could not find PID for process: %s", access.Process)
		}
	}
}

// Удаление файла
func (fm *FileMonitor) removeFile(pod *v1.Pod, container *v1.Container, filePath string) error {
	cmd := []string{"rm", "-f", filePath}
	_, err := fm.executeCommandInContainer(pod, container, cmd)
	return err
}

// Убийство процесса
func (fm *FileMonitor) killProcess(pod *v1.Pod, container *v1.Container, pid string) error {
	// Пробуем мягко завершить процесс
	cmd := []string{"kill", pid}
	_, err := fm.executeCommandInContainer(pod, container, cmd)

	if err != nil {
		// Если не удалось, пробуем жестко завершить
		cmd = []string{"kill", "-9", pid}
		_, err = fm.executeCommandInContainer(pod, container, cmd)
	}

	return err
}

// Поиск PID процесса по команде
func (fm *FileMonitor) findProcessPIDByCommand(processes []ProcessInfo, command string) string {
	for _, process := range processes {
		if strings.Contains(process.Command, command) ||
			strings.Contains(strings.Join(process.Args, " "), command) {
			return process.PID
		}
	}
	return ""
}

// Уведомления об удалении файлов
func (fm *FileMonitor) sendFileRemediationNotification(pod *v1.Pod, container *v1.Container, file SuspiciousFile) {
	// Здесь можно реализовать отправку уведомлений (Slack, Email, etc.)
	log.Printf("📢 Remediation notification: Removed suspicious file from %s/%s: %s (%s)",
		pod.Namespace, pod.Name, file.Path, file.Reason)

	// В реальной реализации можно отправить в систему логирования или SIEM
}

// Уведомления об убийстве процессов
func (fm *FileMonitor) sendProcessRemediationNotification(pod *v1.Pod, container *v1.Container, access SuspiciousAccess, pid string) {
	// Здесь можно реализовать отправку уведомлений (Slack, Email, etc.)
	log.Printf("📢 Remediation notification: Killed suspicious process in %s/%s: %s (PID: %s) accessing %s",
		pod.Namespace, pod.Name, access.Process, pid, access.FilePath)

	// В реальной реализации можно отправить в систему логирования или SIEM
}
