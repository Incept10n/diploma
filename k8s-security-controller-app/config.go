package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v2"
)

type SecurityConfig struct {
	Cron           CronConfig           `yaml:"cron"`
	FileMonitoring FileMonitoringConfig `yaml:"fileMonitoring"`
	Secrets        SecretsConfig        `yaml:"secrets"`
	FalcoWebhook   FalcoWebhookConfig   `yaml:"falcoWebhook"`
	Logging        LoggingConfig        `yaml:"logging"`
}

type FalcoWebhookConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listenAddr"`
	Secret     string `yaml:"secret"`
	Actions    struct {
		DeletePod        bool `yaml:"deletePod"`
		TerminateProcess bool `yaml:"terminateProcess"`
	} `yaml:"actions"`
}

type CronConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MonitoringInterval time.Duration `yaml:"monitoringInterval"`
	MonitoredPaths     []string      `yaml:"monitoredPaths"`
	SuspiciousPatterns []string      `yaml:"suspiciousPatterns"`
	AllowedCommands    []string      `yaml:"allowedCommands"`
}

type FileMonitoringConfig struct {
	Enabled             bool          `yaml:"enabled"`
	MonitoringInterval  time.Duration `yaml:"monitoringInterval"`
	ProtectedPaths      []string      `yaml:"protectedPaths"`
	ForbiddenExtensions []string      `yaml:"forbiddenExtensions"`
	AllowedWritePaths   []string      `yaml:"allowedWritePaths"`
	MaxFileSize         int64         `yaml:"maxFileSize"`
}

type SecretsConfig struct {
	Enabled                  bool     `yaml:"enabled"`
	ProtectedPaths           []string `yaml:"protectedPaths"`
	SuspiciousAccessPatterns []string `yaml:"suspiciousAccessPatterns"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

func loadSecurityConfig() (*SecurityConfig, error) {
	// Пытаемся загрузить из ConfigMap (внутри контейнера)
	log.Println("Setting the path for security-config.yaml")
	configPath := "/config/security-config.yaml"
	var data []byte
	var err error
	if data, err = ioutil.ReadFile(configPath); err == nil {
		log.Println("Trying to load the security-config.yaml")
		var config SecurityConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			return &config, nil
		}
	}

	log.Printf("Failed to read config file: %v", err)
	return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
}
