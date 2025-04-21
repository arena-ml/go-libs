package log

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-colorable"
	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otelLog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const EnvKeyOTelExporterEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"
const EnvKeyLogLevel = "LOG_LEVEL"
const EnvKeyOTelLogLevel = "OTEL_LOG_LEVEL"
const EnvKeyLogFormat = "LOG_FORMAT"
const EnvValLogFormatJSON = "json"
const EnvValLogFormatConsole = "console"
const EnvKeyLogEnableStackTrace = "LOG_ENABLE_STACKTRACE"

var logger *zap.Logger

var otelZapCore *otelzap.Core

var otelLogProvider *log.LoggerProvider

func Init(app string, res *resource.Resource, ctx context.Context) error {
	if logger != nil {
		return fmt.Errorf("logger already initialized")
	}

	var cores []zapcore.Core
	level := giveZapLevel()
	enc := zap.NewProductionEncoderConfig()
	enc.EncodeTime = zapcore.ISO8601TimeEncoder
	enc.EncodeCaller = zapcore.ShortCallerEncoder

	var encoder zapcore.Encoder
	logSync := zapcore.AddSync(os.Stdout)
	if os.Getenv(EnvKeyLogFormat) == EnvValLogFormatConsole || os.Getenv(EnvKeyLogFormat) == "" {
		logSync = zapcore.AddSync(colorable.NewColorableStdout())
		enc.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(enc)
	} else {
		logSync = zapcore.AddSync(os.Stdout)
		encoder = zapcore.NewJSONEncoder(enc)
	}

	stdOutCore := zapcore.NewCore(encoder, logSync, level)

	cores = append(cores, stdOutCore)

	var err error
	var lp *log.LoggerProvider
	otelEndpoint := os.Getenv(EnvKeyOTelExporterEndpoint)
	if otelEndpoint != "" {
		lp, err = OTelLogProvider(res, ctx)
	}

	if err != nil {
		return err
	}

	if lp != nil {
		otelZapCore = otelzap.NewCore(app, otelzap.WithLoggerProvider(lp))
		cores = append(cores, otelZapCore)
	}

	logOpts := []zap.Option{zap.AddCaller()}
	if os.Getenv(EnvKeyLogEnableStackTrace) == "true" {
		logOpts = append(logOpts, zap.AddStacktrace(zap.ErrorLevel))
	}

	logger = zap.New(
		zapcore.NewTee(cores...),
		logOpts...,
	)

	zap.ReplaceGlobals(logger)
	return nil
}

func L() *zap.Logger {
	return zap.L()
}

func S() *zap.SugaredLogger {
	return zap.S()
}

func Sync() (err error) {
	if logger != nil {
		return logger.Sync()
	}

	return fmt.Errorf("logger not initialized")
}

func Shutdown(ctx context.Context) error {
	var errs []error

	err := zap.L().Sync()
	if err != nil {
		errs = append(errs, err)
	}

	if otelLogProvider != nil {
		err = otelLogProvider.Shutdown(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// OTelLogProvider otel exporter related setting should be set in env
func OTelLogProvider(res *resource.Resource, ctx context.Context) (lp *log.LoggerProvider, err error) {
	exporter, err := otlploggrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	otelLogLevel := giveOTelLogLevel()
	processor := &SeverityProcessor{
		Processor: log.NewBatchProcessor(exporter),
		Min:       otelLogLevel,
	}

	lp = log.NewLoggerProvider(
		log.WithProcessor(processor),
		log.WithResource(res),
	)

	global.SetLoggerProvider(lp)
	otelLogProvider = lp

	return lp, nil
}

func giveZapLevel() zapcore.Level {
	lvl := os.Getenv(EnvKeyLogLevel)

	switch strings.ToLower(lvl) {
	case "":
		return zapcore.InfoLevel
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func giveOTelLogLevel() otelLog.Severity {
	lvl := strings.ToLower(os.Getenv(EnvKeyOTelLogLevel))

	switch lvl {
	case "":
		return otelLog.SeverityInfo
	case "warn":
		return otelLog.SeverityWarn
	case "debug":
		return otelLog.SeverityDebug
	case "info":
		return otelLog.SeverityInfo
	case "error":
		return otelLog.SeverityError
	default:
		return otelLog.SeverityInfo
	}
}

// Cl impl
func Cl() *zap.SugaredLogger {
	return zap.L().Sugar()
}

// SeverityProcessor filters out log records with severity below the given threshold.
type SeverityProcessor struct {
	log.Processor
	Min otelLog.Severity
}

// OnEmit passes ctx and record to the wrapped sdklog.Processor
// if the record's severity is greater than or equal to p.Min.
// Otherwise, the record is dropped (the wrapped processor is not invoked).
func (p *SeverityProcessor) OnEmit(ctx context.Context, record *log.Record) error {
	if record.Severity() != otelLog.SeverityUndefined && record.Severity() < p.Min {
		return nil
	}
	return p.Processor.OnEmit(ctx, record)
}
