package lib

import "sync"

type BaseStore interface {
	Get(path string) (map[string]any, bool)
	GetTarget(path string) *URLTrie
	GetAll() map[string]map[string]any
	Add(path string, data map[string]any)
	Update(path string, data map[string]any)
	Remove(path string) map[string]any
}

type MemoryStore struct {
	routes map[string]map[string]any
	urls   *URLTrie

	lock *sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		routes: make(map[string]map[string]any),
		urls:   NewURLTrie(""),
		lock:   &sync.RWMutex{},
	}
}

func cleanPath(path string) string {
	return trimPrefix(path)
}

func (store *MemoryStore) Get(path string) (map[string]any, bool) {
	store.lock.RLock()
	route, exists := store.routes[cleanPath(path)]
	store.lock.RUnlock()
	return route, exists
}

func (store *MemoryStore) GetTarget(path string) *URLTrie {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.urls.Get(cleanPath(path))
}

func (store *MemoryStore) GetAll() map[string]map[string]any {
	store.lock.RLock()
	defer store.lock.RUnlock()
	return store.routes
}

func (store *MemoryStore) Add(path string, data map[string]any) {
	store.lock.Lock()
	defer store.lock.Unlock()

	path = cleanPath(path)
	store.routes[path] = data
	store.urls.Add(path, data)
}

func (store *MemoryStore) Update(path string, data map[string]any) {
	store.lock.Lock()
	defer store.lock.Unlock()

	path = cleanPath(path)
	dataOrg := store.routes[path]
	if dataOrg == nil {
		store.routes[path] = data
		return
	}
	for k, v := range data {
		dataOrg[k] = v
	}
}

func (store *MemoryStore) Remove(path string) map[string]any {
	store.lock.Lock()
	defer store.lock.Unlock()

	path = cleanPath(path)
	route, exist := store.routes[path]
	if exist {
		delete(store.routes, path)
	}
	store.urls.Remove(path)
	return route
}
