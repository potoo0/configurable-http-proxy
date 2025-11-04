package lib

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_Get(t *testing.T) {
	t.Run("returns the data for the specified path", func(t *testing.T) {
		subject := NewMemoryStore()
		data := map[string]any{"test": "value"}
		subject.Add("/myRoute", data)

		dataGet, _ := subject.Get("/myRoute")
		assert.Equal(t, data, dataGet)
	})

	t.Run("returns undefined when not found", func(t *testing.T) {
		subject := NewMemoryStore()
		_, exists := subject.Get("/wut")
		assert.False(t, exists)
	})
}

func TestMemoryStore_GetTarget(t *testing.T) {
	subject := NewMemoryStore()
	data := map[string]any{"target": "http://localhost:8213"}
	subject.Add("/myRoute", data)

	target := subject.GetTarget("/myRoute")
	assert.Equal(t, "/myRoute", target.prefix)
	dataGet, ok := target.data.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, data, dataGet)
}

func TestMemoryStore_GetAll(t *testing.T) {
	t.Run("returns all routes", func(t *testing.T) {
		subject := NewMemoryStore()

		data1 := map[string]any{"test": "value1"}
		data2 := map[string]any{"test": "value2"}
		subject.Add("/myRoute", data1)
		subject.Add("/myOtherRoute", data2)

		routes := subject.GetAll()
		assert.Len(t, routes, 2)
		assert.Equal(t, data1, routes["/myRoute"])
		assert.Equal(t, data2, routes["/myOtherRoute"])
	})

	t.Run("returns a blank object when no routes defined", func(t *testing.T) {
		subject := NewMemoryStore()
		routes := subject.GetAll()
		assert.Empty(t, routes)
	})
}

// overwrites any existing values
func TestMemoryStore_Add(t *testing.T) {
	subject := NewMemoryStore()

	data1 := map[string]any{"test": "value1"}
	data2 := map[string]any{"test": "value2"}
	subject.Add("/myRoute", data1)
	subject.Add("/myRoute", data2)

	route, exists := subject.Get("/myRoute")
	assert.True(t, exists)
	assert.Equal(t, data2, route)
}

// merges supplied data with existing data
func TestMemoryStore_Update(t *testing.T) {
	subject := NewMemoryStore()

	data1 := map[string]any{"version": 1, "test": "value"}
	data2 := map[string]any{"version": 2}
	subject.Add("/myRoute", data1)
	subject.Update("/myRoute", data2)

	route, _ := subject.Get("/myRoute")
	assert.Equal(t, 2, route["version"])
	assert.Equal(t, "value", route["test"])
}

func TestMemoryStore_Remove(t *testing.T) {
	t.Run("removes a route from the table", func(t *testing.T) {
		subject := NewMemoryStore()
		data := map[string]any{"test": "value"}
		subject.Add("/myRoute", data)
		subject.Remove("/myRoute")
		_, exists := subject.Get("/myRoute")
		assert.False(t, exists)
	})

	t.Run("doesn't explode when route is not defined", func(t *testing.T) {
		subject := NewMemoryStore()
		// would blow up if an error was thrown
		assert.NotPanics(t, func() {
			subject.Remove("/myRoute/foo/bar")
		})
	})
}

func TestMemoryStoreConcurrentRW(_ *testing.T) {
	var subject BaseStore = NewMemoryStore()
	data := map[string]any{"test": "value"}

	wg := sync.WaitGroup{}
	wg.Add(4)

	for range 4 {
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				subject.Add("/myRoute", data)
				subject.Get("/myRoute")
				subject.GetTarget("/myRoute")
				subject.GetAll()
				subject.Update("/myRoute", data)
				subject.Remove("/myRoute")
			}
		}()
	}
	wg.Wait()
}
