package fanoutoutput

import (
	"context"
	"errors"

	"docker-net-ebpf/netwatch"
)

type Output struct {
	outputs []netwatch.Output
}

func New(outputs ...netwatch.Output) *Output {
	filtered := make([]netwatch.Output, 0, len(outputs))
	for _, output := range outputs {
		if output != nil {
			filtered = append(filtered, output)
		}
	}
	return &Output{outputs: filtered}
}

func (o *Output) Write(ctx context.Context, samples []netwatch.TrafficSample) error {
	var errs []error
	for _, output := range o.outputs {
		if err := output.Write(ctx, samples); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (o *Output) Close() error {
	var errs []error
	for _, output := range o.outputs {
		if err := output.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
