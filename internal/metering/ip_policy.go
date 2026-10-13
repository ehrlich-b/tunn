package metering

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ehrlich-b/tunn/internal/ippolicy"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// IPPolicyBackend is implemented by the login authority and its node client.
type IPPolicyBackend interface {
	IPPolicy(context.Context, *pb.IPPolicyRequest) (*pb.IPPolicy, error)
}

func (s *Store) initIPPolicies() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ip_policies (
 owner TEXT NOT NULL, endpoint TEXT NOT NULL, data BLOB NOT NULL,
 PRIMARY KEY(owner,endpoint));`)
	return err
}

func (s *Store) IPPolicy(ctx context.Context, in *pb.IPPolicyRequest) (*pb.IPPolicy, error) {
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "policy required")
	}
	in = proto.Clone(in).(*pb.IPPolicyRequest)
	if in.Owner == "" || len(in.Owner) > 128 || in.Endpoint != "" && !resourceName.MatchString(in.Endpoint) {
		return nil, status.Error(codes.InvalidArgument, "invalid owner or endpoint")
	}
	if in.Operation != "get" && in.Operation != "set" && in.Operation != "delete" {
		return nil, status.Error(codes.InvalidArgument, "invalid policy operation")
	}
	if in.Operation != "set" && (len(in.AllowCidrs) > 0 || len(in.DenyCidrs) > 0) {
		return nil, status.Error(codes.InvalidArgument, "CIDRs are only accepted when setting a policy")
	}
	var err error
	if in.AllowCidrs, err = ippolicy.Normalize(in.AllowCidrs); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if in.DenyCidrs, err = ippolicy.Normalize(in.DenyCidrs); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	out := &pb.IPPolicy{}
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		in.Owner, err = canonicalOwner(tx, in.Owner)
		if err != nil {
			return err
		}
		if in.Operation != "get" {
			if err = s.sharingMutationAdmission(ctx, tx, in.Owner); err != nil {
				return err
			}
			if suspended, err := operationallySuspended(tx, in.Owner); err != nil {
				return err
			} else if suspended {
				return status.Error(codes.PermissionDenied, "active owner required")
			}
		}
		if in.Operation == "set" {
			var exists, total, owned int
			if err = tx.QueryRowContext(ctx, `SELECT
    (SELECT count(*) FROM ip_policies WHERE owner=? AND endpoint=?),
    (SELECT count(*) FROM ip_policies),
    (SELECT count(*) FROM ip_policies WHERE owner=? AND endpoint<>'')`, in.Owner, in.Endpoint, in.Owner).Scan(&exists, &total, &owned); err != nil {
				return err
			}
			if exists == 0 && (total >= s.maxGrants || in.Endpoint != "" && owned >= s.maxOwnerResources) {
				return ErrCapacity
			}
			data, err := json.Marshal(&pb.IPPolicy{AllowCidrs: in.AllowCidrs, DenyCidrs: in.DenyCidrs, Configured: true})
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO ip_policies(owner,endpoint,data) VALUES(?,?,?)
    ON CONFLICT(owner,endpoint) DO UPDATE SET data=excluded.data`, in.Owner, in.Endpoint, data); err != nil {
				return err
			}
		}
		if in.Operation == "delete" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM ip_policies WHERE owner=? AND endpoint=?`, in.Owner, in.Endpoint); err != nil {
				return err
			}
		}
		var data []byte
		err = tx.QueryRowContext(ctx, `SELECT data FROM ip_policies WHERE owner=? AND endpoint=?`, in.Owner, in.Endpoint).Scan(&data)
		out.Inherited = in.Endpoint != "" && errors.Is(err, sql.ErrNoRows)
		if out.Inherited {
			err = tx.QueryRowContext(ctx, `SELECT data FROM ip_policies WHERE owner=? AND endpoint=''`, in.Owner).Scan(&data)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		inherited := out.Inherited
		if err = json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("invalid persisted IP policy: %w", err)
		}
		out.Inherited = inherited
		return nil
	})
	return out, err
}

func (r *Remote) IPPolicy(ctx context.Context, in *pb.IPPolicyRequest) (*pb.IPPolicy, error) {
	c, err := r.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := rpcContext(ctx)
	defer cancel()
	out, err := c.IPPolicy(ctx, in)
	return out, decodeAdmissionError(err)
}
