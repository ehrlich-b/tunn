package store

import (
	"crypto/subtle"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// User represents a user from users.yaml
type User struct {
	Token string `yaml:"token"`
	Plan  string `yaml:"plan"` // "free" or "pro"
}

// UserStore manages users loaded from users.yaml
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User // keyed by email
}

// NewUserStore creates a new user store, optionally loading from a YAML file
func NewUserStore(filePath string) (*UserStore, error) {
	store := &UserStore{
		users: make(map[string]*User),
	}

	if filePath != "" {
		if err := store.Load(filePath); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// Load loads users from a YAML file
func (s *UserStore) Load(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var rawUsers map[string]*User
	if err := yaml.Unmarshal(data, &rawUsers); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Normalize email keys to lowercase
	s.users = make(map[string]*User)
	for email, user := range rawUsers {
		s.users[strings.ToLower(email)] = user
	}

	return nil
}

// ValidateToken checks if a token is valid and returns the associated email.
// Uses constant-time comparison to prevent timing attacks.
func (s *UserStore) ValidateToken(token string) (email string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for email, user := range s.users {
		if subtle.ConstantTimeCompare([]byte(user.Token), []byte(token)) == 1 {
			return email, true
		}
	}
	return "", false
}

// GetUser returns a user by email
func (s *UserStore) GetUser(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[strings.ToLower(email)]
}

// Count returns the number of users
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// GetTokenMap returns a map of email->token for all users
func (s *UserStore) GetTokenMap() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]string)
	for email, user := range s.users {
		if user.Token != "" {
			result[email] = user.Token
		}
	}
	return result
}
