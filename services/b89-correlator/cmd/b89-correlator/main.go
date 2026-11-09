package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/config"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/engine"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/feedback"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/model"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/resolve"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/risk"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/server"
	"github.com/CyberStill-GmbH/b89-secops/services/b89-correlator/internal/sources"
)

const version = "0.1.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		// Do not log error text: transport and upstream errors may contain sensitive URLs.
		logger.Error("application.failed", "errorType", typeName(err))
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	gatewayToken, err := config.ReadSecret(cfg.GatewayTokenFile)
	if err != nil {
		return err
	}
	serviceToken, err := config.ReadSecret(cfg.ServiceTokenFile)
	if err != nil {
		return err
	}
	readToken, err := config.ReadSecret(cfg.ReadTokenFile)
	if err != nil {
		return err
	}
	aliases, err := config.ReadList(cfg.AliasesFile)
	if err != nil {
		return err
	}
	criticality, err := config.ReadList(cfg.CriticalityFile)
	if err != nil {
		return err
	}
	resolver := resolve.New(aliases, cfg.UserDomain)
	policy := risk.DefaultPolicy()
	policy.HalfLife, policy.Threshold, policy.MinLevel = cfg.HalfLife, cfg.Threshold, cfg.MinLevel
	criticalityOf := func(entity model.Entity) string {
		return criticality[resolver.Canonical(entity.Key())]
	}
	eng := risk.NewEngine(policy, risk.DefaultPatterns(), resolver, criticalityOf, cfg.GroupMinLevel)

	fbPolicy := feedback.DefaultPolicy()
	fbPolicy.MinFalsePositives = cfg.FPMin
	fbPolicy.SuppressionTTL = cfg.SuppressionTTL
	fbPolicy.AutoSuppress = cfg.AutoSuppress
	fbPolicy.ProtectedRules = make(map[string]bool, len(cfg.ProtectedRules))
	for _, id := range cfg.ProtectedRules {
		fbPolicy.ProtectedRules[id] = true
	}

	client, err := sources.NewHTTPClient(cfg.CAFile, 30*time.Second)
	if err != nil {
		return err
	}
	gateway := &sources.WazuhGateway{BaseURL: cfg.GatewayURL, Token: func() string { return gatewayToken }, Client: client, MinLevel: cfg.MinLevel, PageSize: cfg.PageSize}
	api := &sources.B89API{BaseURL: cfg.APIURL, Token: func() string { return serviceToken }, Client: client}
	runner := engine.New(engine.Options{
		Backfill: cfg.Backfill, PollInterval: cfg.PollInterval, FeedbackInterval: cfg.FeedbackInterval,
		Lag: cfg.Lag, Overlap: cfg.Overlap, Emit: cfg.Emit, EmitMaxAge: cfg.EmitMaxAge,
		EmitMaxPerHour: cfg.EmitMaxPerHour, Audit: true, FeedbackLookback: cfg.FeedbackLookback,
		Feedback: fbPolicy,
	}, eng, resolver, gateway, api, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go runner.Run(ctx)
	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: (&server.Server{Runner: runner, ReadToken: func() string { return readToken }, Now: time.Now, Version: version}).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.ListenAndServe()
	}()
	log.Info("application.started", "version", version, "pollIntervalSeconds", cfg.PollInterval.Seconds(), "emitEnabled", cfg.Emit)
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil {
		return err
	}
	<-serveErr
	return nil
}

func typeName(err error) string {
	if err == nil {
		return "unknown"
	}
	return fmt.Sprintf("%T", err)
}
