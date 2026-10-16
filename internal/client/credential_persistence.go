package client

import "context"

// credentialPersistence separates durable file operations from renewal policy.
// Publishers always use disk persistence; lifetime simulations can keep state
// in memory while exercising the same rotation and rejection decisions.
type credentialPersistence interface {
	lock(context.Context, string) (func(), error)
	read(string) (*savedCredentials, error)
	write(string, *savedCredentials) error
	mirror(string, string) error
}

type diskCredentialPersistence struct{}

func (diskCredentialPersistence) lock(ctx context.Context, dir string) (func(), error) {
	return lockCredentials(ctx, dir)
}
func (diskCredentialPersistence) read(path string) (*savedCredentials, error) {
	return readCredentialState(path)
}
func (diskCredentialPersistence) write(path string, state *savedCredentials) error {
	return saveCredentialState(path, state)
}
func (diskCredentialPersistence) mirror(dir, token string) error {
	_, err := writePrivateTokenFile(dir, "token", token)
	return err
}
