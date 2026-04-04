package main

import "time"

type SecurityConfig struct {
	Cron    CronConfig    `yaml:"cron"`
	Logging LoggingConfig `yaml:"logging"`
}

type CronConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MonitoringInterval time.Duration `yaml:"monitoringInterval"`
	MonitoredPaths     []string      `yaml:"monitoredPaths"`
	SuspiciousPatterns []string      `yaml:"suspiciousPatterns"`
	AllowedCommands    []string      `yaml:"allowedCommands"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}
