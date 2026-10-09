package openapi

import (
	"encoding/json"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-openapi/generator"
	"github.com/BladiCreator/go-modular-auth-openapi/spec"
)

type OpenAPIGenerator interface {
	Generate() (*spec.Document, error)
	GenerateJSON(indent bool) ([]byte, error)
}

type service struct {
	ctx *sdk.Context
	cfg Config
	gen *generator.Generator
}

var _ OpenAPIGenerator = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx: ctx,
		cfg: cfg,
		gen: generator.New(cfg.Title, cfg.Version, cfg.Description),
	}
}

func (s *service) Generate() (*spec.Document, error) {
	var installedIDs []string
	if s.ctx != nil && s.ctx.Core() != nil && s.ctx.Core().Registry() != nil {
		installedIDs = s.ctx.Core().Registry().Modules()
	}
	return s.gen.Generate(installedIDs), nil
}

func (s *service) GenerateJSON(indent bool) ([]byte, error) {
	doc, err := s.Generate()
	if err != nil {
		return nil, err
	}
	if indent {
		return json.MarshalIndent(doc, "", "  ")
	}
	return json.Marshal(doc)
}
