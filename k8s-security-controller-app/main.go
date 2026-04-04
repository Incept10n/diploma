package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig string
	var master string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()

	// Создаем конфигурацию для подключения к Kubernetes
	config, err := buildConfig(master, kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	// Создаем клиент Kubernetes
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	// Загружаем конфигурацию безопасности
	securityConfig, err := loadSecurityConfig()
	if err != nil {
		log.Printf("Warning: Could not load security config, using defaults: %v", err)
		securityConfig = getDefaultSecurityConfig()
	}

	// Создаем контроллер cron
	cronController := NewCronController(clientset, securityConfig)

	// Запускаем контроллер
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received termination signal, shutting down...")
		cancel()
	}()

	log.Println("Starting Kubernetes Security Controller - Cron Monitor")
	log.Printf("Monitoring interval: %v", securityConfig.Cron.MonitoringInterval)

	// Запускаем мониторинг
	cronController.StartMonitoring(ctx)
}

func buildConfig(masterUrl, kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags(masterUrl, kubeconfigPath)
	}
	return rest.InClusterConfig()
}

func loadSecurityConfig() (*SecurityConfig, error) {
	// Пока возвращаем дефолтную конфигурацию
	// Позже реализуем загрузку из ConfigMap или файла
	return getDefaultSecurityConfig(), nil
}

func getDefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Cron: CronConfig{
			Enabled:            true,
			MonitoringInterval: 30 * time.Second,
			MonitoredPaths: []string{
				"/etc/crontab",
				"/etc/cron.d/",
				"/var/spool/cron/crontabs/",
				"/etc/cron.hourly/",
				"/etc/cron.daily/",
				"/etc/cron.weekly/",
				"/etc/cron.monthly/",
			},
			SuspiciousPatterns: []string{
				"* * * * * *", // слишком частое выполнение
				"*/1 *",       // каждую минуту
				"sh -c",       // выполнение shell-команд
				"bash -c",     // выполнение bash-команд
				"wget",        // скачивание файлов
				"curl",        // HTTP-запросы
				"nc ",         // netcat
				"ncat",        // ncat
				"/tmp/",       // использование временных директорий
				"/dev/shm/",   // shared memory
			},
			AllowedCommands: []string{
				"/usr/bin/apt",
				"/usr/bin/yum",
				"/usr/bin/systemctl",
				// Добавь сюда команды, которые должны быть разрешены
			},
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}
