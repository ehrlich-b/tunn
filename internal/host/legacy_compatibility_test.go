package host
import("context";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"net/http";"testing";"time";"github.com/ehrlich-b/tunn/internal/store")
func solBaseNormalizeStripeEvent(event StripeEvent, body []byte) (store.BillingEvent, error) {
	digest := sha256.Sum256(body)
	out := store.BillingEvent{Provider: "stripe", ID: event.ID, Type: event.Type, PayloadSHA256: hex.EncodeToString(digest[:])}
	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		var sub StripeSubscription
		if err := json.Unmarshal(event.Data.Object, &sub); err != nil {
			return out, err
		}
		out.CustomerID, out.SubscriptionID, out.Supported = sub.Customer, sub.ID, true
	case "checkout.session.completed":
		var session struct {
			ID           string `json:"id"`
			Customer     string `json:"customer"`
			Subscription string `json:"subscription"`
			Mode         string `json:"mode"`
			Reference    string `json:"client_reference_id"`
		}
		if err := json.Unmarshal(event.Data.Object, &session); err != nil {
			return out, err
		}
		out.CustomerID, out.SubscriptionID, out.Supported = session.Customer, session.Subscription, session.Mode == "subscription"
		out.CheckoutReference = session.Reference
		out.SessionID, out.CompletedAt = session.ID, event.Created
	}
	return out, nil
}


func TestReviewLegacyNormalizationCompatibility(t *testing.T){
 for _,typ:=range []string{"charge.refunded","charge.dispute.created","invoice.paid","invoice.payment_succeeded"}{t.Run(typ,func(t *testing.T){
 p,db:=stripeCorrectnessFixture(t);p.config.StripeWebhookSecret="whsec_sol_local_fixture"
 body:=fmt.Sprintf(`{"id":"evt_legacy","type":%q,"data":{"object":{"id":"ch_fixture","charge":"ch_fixture","customer":"cus_fixture","subscription":"sub_fixture"}}}`,typ)
 var event StripeEvent;if err:=json.Unmarshal([]byte(body),&event);err!=nil{t.Fatal(err)}
 old,err:=solBaseNormalizeStripeEvent(event,[]byte(body));if err!=nil{t.Fatal(err)}
 ops:=store.NewOperationsStore(db,nil)
 first,err:=ops.ProcessBillingEvent(context.Background(),old);if err!=nil||first.State!="ignored"{t.Fatal(first,err)}
 repeat,err:=ops.ProcessBillingEvent(context.Background(),old);if err!=nil||!repeat.Duplicate||repeat.State!="ignored"{t.Fatal(repeat,err)}
 now,err:=normalizeStripeEvent(event,[]byte(body));if err!=nil{t.Fatal(err)}
 if old.PayloadSHA256!=now.PayloadSHA256{t.Fatal("body digest changed")}
 _,err=ops.ProcessBillingEvent(context.Background(),now);
 response:=stripeFixtureRequest(p,body,signedStripeFixture(body,p.config.StripeWebhookSecret,time.Now().Unix()))
 if response.Code!=http.StatusOK{t.Fatal(response.Code,response.Body)}
 t.Logf("base first=%s repeat duplicate=%v; equal payload SHA=%v; upgraded replay err=%v; real signed webhook HTTP=%d body=%q",first.State,repeat.Duplicate,old.PayloadSHA256==now.PayloadSHA256,err,response.Code,response.Body.String())
 })}
}
