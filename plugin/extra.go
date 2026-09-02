package plugin

import "github.com/BladiCreator/go-modular-auth/domain/entity"

// ExtraContainer provides a reusable map for dynamic metadata with Set and Get methods.
// Embed plugin.ExtraContainer in DTO parameter structs to eliminate repetitive metadata handling code.
// TODO: Use entity.ExtraContainer directly instead of aliasing.
type ExtraContainer = entity.ExtraContainer
