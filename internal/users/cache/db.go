// Package cache handles transaction with an underlying database to cache user and group information.
package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"github.com/ubuntu/decorate"
	"go.etcd.io/bbolt"
)

var (
	dbName = "authd.db"
)

const (
	userByNameBucketName   = "UserByName"
	userByIDBucketName     = "UserByID"
	groupByNameBucketName  = "GroupByName"
	groupByIDBucketName    = "GroupByID"
	userToGroupsBucketName = "UserToGroups"
	groupToUsersBucketName = "GroupToUsers"
	userToBrokerBucketName = "UserToBroker"
)

var (
	allBuckets = [][]byte{
		[]byte(userByNameBucketName), []byte(userByIDBucketName),
		[]byte(groupByNameBucketName), []byte(groupByIDBucketName),
		[]byte(userToGroupsBucketName), []byte(groupToUsersBucketName),
		[]byte(userToBrokerBucketName),
	}
)

// Cache is our database API.
type Cache struct {
	db *bbolt.DB
	mu sync.RWMutex
}

// UserDB is the public type that is shared to external packages.
type UserDB struct {
	Name  string
	UID   uint32
	GID   uint32
	Gecos string // Gecos is an optional field. It can be empty.
	Dir   string
	Shell string

	// Shadow entries
	LastPwdChange  int
	MaxPwdAge      int
	PwdWarnPeriod  int
	PwdInactivity  int
	MinPwdAge      int
	ExpirationDate int
}

// GroupDB is the struct stored in json format in the bucket.
type GroupDB struct {
	Name  string
	GID   uint32
	Users []string
}

// userToGroupsDB is the struct stored in json format to match uid to gids in the bucket.
type userToGroupsDB struct {
	UID  uint32
	GIDs []uint32
}

// groupToUsersDB is the struct stored in json format to match gid to uids in the bucket.
type groupToUsersDB struct {
	GID  uint32
	UIDs []uint32
}

// New creates a new database cache by creating or opening the underlying db.
func New(cacheDir string) (cache *Cache, err error) {
	dbPath := filepath.Join(cacheDir, dbName)
	defer decorate.OnError(&err, "could not create new database object at %q", dbPath)

	var db *bbolt.DB
	db, err = openAndInitDB(dbPath)
	if err != nil {
		return nil, err
	}

	return &Cache{db: db, mu: sync.RWMutex{}}, nil
}

// openAndInitDB open a pre-existing database and potentially initializes its buckets.
func openAndInitDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("can't open database file: %v", err)
	}
	// Fail if permissions are not 0600
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("can't stat database file: %v", err)
	}
	perm := fileInfo.Mode().Perm()
	if perm != 0600 {
		return nil, fmt.Errorf("wrong file permission for %s: %o", path, perm)
	}

	// Create buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		var allBucketsNames []string
		for _, bucket := range allBuckets {
			allBucketsNames = append(allBucketsNames, string(bucket))
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}

		// Clear up any unknown buckets
		var bucketNamesToDelete [][]byte
		err = tx.ForEach(func(name []byte, _ *bbolt.Bucket) error {
			if slices.Contains(allBucketsNames, string(name)) {
				return nil
			}
			bucketNamesToDelete = append(bucketNamesToDelete, name)
			return nil
		})
		if err != nil {
			return err
		}
		for _, bucketName := range bucketNamesToDelete {
			// We are in a RW transaction.
			_ = tx.DeleteBucket(bucketName)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Close closes the db and signal the monitoring goroutine to stop.
func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.db.Close()
}

// RemoveDb removes the database file.
func RemoveDb(cacheDir string) error {
	return os.Remove(filepath.Join(cacheDir, dbName))
}

// bucketWithName is a wrapper adding the name on top of a bbolt Bucket.
type bucketWithName struct {
	name string
	*bbolt.Bucket
}

// getAllBuckets returns all buckets that should be stored in the database.
func getAllBuckets(tx *bbolt.Tx) (map[string]bucketWithName, error) {
	buckets := make(map[string]bucketWithName)
	for _, name := range allBuckets {
		b := tx.Bucket(name)
		if b == nil {
			return nil, fmt.Errorf("bucket %v not found", name)
		}
		buckets[string(name)] = bucketWithName{name: string(name), Bucket: b}
	}

	return buckets, nil
}

// getBucket returns one bucket for a given name.
func getBucket(tx *bbolt.Tx, name string) (bucketWithName, error) {
	b := tx.Bucket([]byte(name))
	if b == nil {
		return bucketWithName{}, fmt.Errorf("bucket %v not found", name)
	}
	return bucketWithName{name: name, Bucket: b}, nil
}

// getFromBucket is a generic function to get any value of given type from a bucket. It returns an error if
// the returned value (json) could not be unmarshalled to the returned struct.
func getFromBucket[T any, K uint32 | string](bucket bucketWithName, key K) (T, error) {
	// TODO: switch to https://github.com/golang/go/issues/45380 if accepted.
	var k []byte
	switch v := any(key).(type) {
	case uint32:
		k = []byte(strconv.FormatUint(uint64(v), 10))
	case string:
		k = []byte(v)
	default:
		panic(fmt.Sprintf("unhandled type: %T", key))
	}

	var r T

	data := bucket.Get(k)
	if data == nil {
		return r, NoDataFoundError{key: string(k), bucketName: bucket.name}
	}

	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("can't unmarshal bucket %q for key %v: %v", bucket.name, key, err)
	}

	return r, nil
}

// NoDataFoundError is returned when we didn’t find a matching entry.
type NoDataFoundError struct {
	key        string
	bucketName string
}

// Error implements the error interface to return key/bucket name.
func (err NoDataFoundError) Error() string {
	return fmt.Sprintf("no result matching %v in %v", err.key, err.bucketName)
}

// Is makes this error insensitive to the key and bucket name.
func (NoDataFoundError) Is(target error) bool { return target == NoDataFoundError{} }
