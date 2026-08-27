package stripe

const (
	MetadataKeyReferenceID    = "referenceId"
	MetadataKeyEntityType     = "entityType"
	MetadataKeyUserID         = "userId"
	MetadataKeyOrganizationID = "organizationId"
)

// BuildMetadata creates a safe map of metadata key-value pairs for Stripe entities, preserving reserved fields.
func BuildMetadata(referenceID, entityType string, customMeta map[string]string) map[string]string {
	meta := make(map[string]string)

	for k, v := range customMeta {
		if k != MetadataKeyReferenceID && k != MetadataKeyEntityType && k != MetadataKeyUserID && k != MetadataKeyOrganizationID {
			meta[k] = v
		}
	}

	if referenceID != "" {
		meta[MetadataKeyReferenceID] = referenceID
	}
	if entityType != "" {
		meta[MetadataKeyEntityType] = entityType
	}

	return meta
}

// ExtractReferenceID extracts referenceId and entityType from Stripe metadata maps.
func ExtractReferenceID(meta map[string]string) (string, string, bool) {
	if meta == nil {
		return "", "", false
	}
	refID, ok := meta[MetadataKeyReferenceID]
	if !ok || refID == "" {
		return "", "", false
	}
	entityType := meta[MetadataKeyEntityType]
	return refID, entityType, true
}
