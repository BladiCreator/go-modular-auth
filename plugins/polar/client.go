package polar

import (
	"context"
	"fmt"
	"sync"
	"time"

	polarsdk "github.com/polarsource/polar-go"
	polarmodels "github.com/polarsource/polar-go/models/components"
	polarops "github.com/polarsource/polar-go/models/operations"
)

// Client defines the contract for interacting with the Polar API.
type Client interface {
	CreateCustomer(ctx context.Context, email, name, externalID string) (string, error)
	CreateCheckout(ctx context.Context, params CreateCheckoutParams) (string, error)
	CreateCustomerSession(ctx context.Context, polarCustomerID string) (string, error)
	IngestEvent(ctx context.Context, params IngestEventParams) (*IngestEventResult, error)
	GetCustomerState(ctx context.Context, polarCustomerID string) (*CustomerState, error)
}

// polarSDKClient implements Client using the official github.com/polarsource/polar-go SDK.
type polarSDKClient struct {
	sdk *polarsdk.Polar
}

func newSDKClient(accessToken string, server string) *polarSDKClient {
	var opts []polarsdk.SDKOption
	if accessToken != "" {
		opts = append(opts, polarsdk.WithSecurity(accessToken))
	}
	if server == "sandbox" {
		opts = append(opts, polarsdk.WithServerURL("https://sandbox-api.polar.sh"))
	}

	client := polarsdk.New(opts...)
	return &polarSDKClient{sdk: client}
}

func (c *polarSDKClient) CreateCustomer(ctx context.Context, email, name, externalID string) (string, error) {
	ind := polarmodels.CustomerIndividualCreate{
		Email: email,
	}
	if name != "" {
		ind.Name = polarsdk.String(name)
	}
	if externalID != "" {
		ind.ExternalID = polarsdk.String(externalID)
	}

	req := polarmodels.CreateCustomerCreateCustomerIndividualCreate(ind)

	res, err := c.sdk.Customers.Create(ctx, req)
	if err != nil {
		return "", fmt.Errorf("polar: failed to create customer: %w", err)
	}

	if res.Customer != nil && res.Customer.CustomerIndividual != nil {
		return res.Customer.CustomerIndividual.ID, nil
	}
	return "", fmt.Errorf("polar: unexpected response creating customer")
}

func (c *polarSDKClient) CreateCheckout(ctx context.Context, params CreateCheckoutParams) (string, error) {
	req := polarmodels.CheckoutCreate{}

	if params.ProductPriceID != "" {
		req.Products = []string{params.ProductPriceID}
	}
	if params.SuccessURL != "" {
		req.SuccessURL = polarsdk.String(params.SuccessURL)
	}
	if params.CustomerEmail != "" {
		req.CustomerEmail = polarsdk.String(params.CustomerEmail)
	}
	if params.CustomerName != "" {
		req.CustomerName = polarsdk.String(params.CustomerName)
	}
	if params.AllowDiscountCodes {
		req.AllowDiscountCodes = polarsdk.Bool(params.AllowDiscountCodes)
	}
	if params.ReferenceID != "" {
		req.ExternalCustomerID = polarsdk.String(params.ReferenceID)
	}

	res, err := c.sdk.Checkouts.Create(ctx, req)
	if err != nil {
		return "", fmt.Errorf("polar: failed to create checkout: %w", err)
	}

	if res.Checkout != nil {
		return res.Checkout.URL, nil
	}
	return "", fmt.Errorf("polar: unexpected response creating checkout session")
}

func (c *polarSDKClient) CreateCustomerSession(ctx context.Context, polarCustomerID string) (string, error) {
	sessReq := polarmodels.CustomerSessionCustomerIDCreate{
		CustomerID: polarCustomerID,
	}
	req := polarops.CreateCustomerSessionsCreateCustomerSessionCreateCustomerSessionCustomerIDCreate(sessReq)

	res, err := c.sdk.CustomerSessions.Create(ctx, req)
	if err != nil {
		return "", fmt.Errorf("polar: failed to create customer portal session: %w", err)
	}

	if res.CustomerSession != nil {
		return res.CustomerSession.CustomerPortalURL, nil
	}
	return "", fmt.Errorf("polar: unexpected response creating customer session")
}

func (c *polarSDKClient) IngestEvent(ctx context.Context, params IngestEventParams) (*IngestEventResult, error) {
	var event polarmodels.Events

	if params.CustomerExternalID != "" {
		event = polarmodels.CreateEventsEventCreateExternalCustomer(polarmodels.EventCreateExternalCustomer{
			Name:               params.EventName,
			ExternalCustomerID: params.CustomerExternalID,
		})
	} else {
		event = polarmodels.CreateEventsEventCreateCustomer(polarmodels.EventCreateCustomer{
			Name:       params.EventName,
			CustomerID: params.PolarCustomerID,
		})
	}

	req := polarmodels.EventsIngest{
		Events: []polarmodels.Events{event},
	}

	res, err := c.sdk.Events.Ingest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("polar: failed to ingest event: %w", err)
	}

	if res.EventsIngestResponse != nil {
		return &IngestEventResult{
			IngestID:   fmt.Sprintf("ingest_%d", time.Now().UnixNano()),
			RecordedAt: time.Now(),
		}, nil
	}

	return &IngestEventResult{
		IngestID:   fmt.Sprintf("ingest_%d", time.Now().UnixNano()),
		RecordedAt: time.Now(),
	}, nil
}

func (c *polarSDKClient) GetCustomerState(ctx context.Context, polarCustomerID string) (*CustomerState, error) {
	res, err := c.sdk.Customers.Get(ctx, polarCustomerID)
	if err != nil {
		return nil, fmt.Errorf("polar: failed to fetch customer state: %w", err)
	}

	state := &CustomerState{
		PolarCustomerID: polarCustomerID,
	}

	if res.Customer != nil && res.Customer.CustomerIndividual != nil {
		if res.Customer.CustomerIndividual.ExternalID != nil {
			state.ReferenceID = *res.Customer.CustomerIndividual.ExternalID
		}
	}

	return state, nil
}

// mockSDKClient is a thread-safe mock client implementation for unit testing.
type mockSDKClient struct {
	mu             sync.Mutex
	customers      map[string]string // externalID -> customerID
	checkouts      map[string]string // priceID -> checkoutURL
	portalSessions map[string]string // customerID -> portalURL
	events         []IngestEventParams
	states         map[string]*CustomerState // customerID -> CustomerState
}

func newMockClient() *mockSDKClient {
	return &mockSDKClient{
		customers:      make(map[string]string),
		checkouts:      make(map[string]string),
		portalSessions: make(map[string]string),
		states:         make(map[string]*CustomerState),
	}
}

func (m *mockSDKClient) CreateCustomer(_ context.Context, email, name, externalID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	custID := fmt.Sprintf("pol_cust_%d", time.Now().UnixNano())
	if externalID != "" {
		m.customers[externalID] = custID
	}
	return custID, nil
}

func (m *mockSDKClient) CreateCheckout(_ context.Context, params CreateCheckoutParams) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	url := fmt.Sprintf("https://polar.sh/checkout/mock_%s", params.ProductPriceID)
	return url, nil
}

func (m *mockSDKClient) CreateCustomerSession(_ context.Context, polarCustomerID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return fmt.Sprintf("https://polar.sh/portal/session_%s", polarCustomerID), nil
}

func (m *mockSDKClient) IngestEvent(_ context.Context, params IngestEventParams) (*IngestEventResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = append(m.events, params)
	return &IngestEventResult{
		IngestID:   fmt.Sprintf("ingest_%d", time.Now().UnixNano()),
		RecordedAt: time.Now(),
	}, nil
}

func (m *mockSDKClient) GetCustomerState(_ context.Context, polarCustomerID string) (*CustomerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, ok := m.states[polarCustomerID]; ok {
		return state, nil
	}

	return &CustomerState{
		PolarCustomerID:     polarCustomerID,
		ActiveSubscriptions: []*Subscription{},
		GrantedBenefits:     []*CustomerBenefit{},
		MeterBalances:       []*CustomerMeter{},
	}, nil
}
