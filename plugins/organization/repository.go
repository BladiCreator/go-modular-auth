package organization

// Repository defines the storage contract for persisting and querying organization-related domain entities.
// It composes domain-specific sub-interfaces: OrgRepository, MemberRepository, InvitationRepository, TeamRepository, and RoleRepository.
//
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM, SurrealDB).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormOrganizationRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormOrganizationRepository) GetOrganizationByID(ctx context.Context, id string) (*organization.Organization, error) {
//		var org organization.Organization
//		if err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, organization.ErrOrganizationNotFound
//			}
//			return nil, err
//		}
//		return &org, nil
//	}
type Repository interface {
	OrgRepository
	MemberRepository
	InvitationRepository
	TeamRepository
	RoleRepository
}
