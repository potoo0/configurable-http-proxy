package lib

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func fullTrie() *URLTrie {
	trie := NewURLTrie("")
	paths := []string{"/1", "/2", "/a/b/c/d", "/a/b/d", "/a/b/e", "/b", "/b/c", "/b/c/d"}
	for _, path := range paths {
		trie.Add(path, path)
	}
	return trie
}

func TestURLTrie_Init(t *testing.T) {
	trie := NewURLTrie("")
	assert.Equal(t, trie.prefix, "/")
	assert.Equal(t, trie.size, 0)
	assert.Equal(t, trie.data, nil)
	assert.Equal(t, len(trie.branches), 0)

	trie = NewURLTrie("/foo")
	assert.Equal(t, trie.prefix, "/foo")
	assert.Equal(t, trie.size, 0)
	assert.Equal(t, trie.data, nil)
	assert.Equal(t, len(trie.branches), 0)
}

func TestURLTrie_Root(t *testing.T) {
	trie := NewURLTrie("/")
	trie.Add("/", -1)

	node := trie.Get("/1/etc/etc/")
	assert.NotNil(t, node)
	assert.Equal(t, trie.prefix, "/")
	assert.Equal(t, trie.data, -1)

	node = trie.Get("/")
	assert.NotNil(t, node)
	assert.Equal(t, trie.prefix, "/")
	assert.Equal(t, trie.data, -1)

	node = trie.Get("")
	assert.NotNil(t, node)
	assert.Equal(t, trie.prefix, "/")
	assert.Equal(t, trie.data, -1)
}

func TestURLTrie_Add(t *testing.T) {
	trie := NewURLTrie("")

	trie.Add("foo", 1)
	assert.Equal(t, trie.size, 1)

	assert.Equal(t, trie.data, nil)
	assert.Equal(t, trie.branches["foo"].data, 1)
	assert.Equal(t, trie.branches["foo"].size, 0)

	trie.Add("bar/leaf", 2)
	assert.Equal(t, trie.size, 2)

	bar := trie.branches["bar"]
	assert.Equal(t, bar.prefix, "/bar")
	assert.Equal(t, bar.size, 1)
	assert.Equal(t, bar.branches["leaf"].data, 2)

	trie.Add("/a/b/c/d", 4)
	assert.Equal(t, trie.size, 3)

	var a = trie.branches["a"]
	assert.Equal(t, a.prefix, "/a")
	assert.Equal(t, a.size, 1)
	assert.Equal(t, a.data, nil)

	var b = a.branches["b"]
	assert.Equal(t, b.prefix, "/a/b")
	assert.Equal(t, b.size, 1)
	assert.Equal(t, b.data, nil)

	var c = b.branches["c"]
	assert.Equal(t, c.prefix, "/a/b/c")
	assert.Equal(t, c.size, 1)
	assert.Equal(t, c.data, nil)

	var d = c.branches["d"]
	assert.Equal(t, d.prefix, "/a/b/c/d")
	assert.Equal(t, d.size, 0)
	assert.Equal(t, d.data, 4)
}

func TestURLTrie_Get(t *testing.T) {
	var trie = fullTrie()
	assert.Nil(t, trie.Get("/not/found"))

	var node = trie.Get("/1")
	assert.Equal(t, node.prefix, "/1")
	assert.Equal(t, node.data, "/1")

	node = trie.Get("/1/etc/etc/")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/1")
	assert.Equal(t, node.data, "/1")

	assert.Nil(t, trie.Get("/a"))
	assert.Nil(t, trie.Get("/a/b/c"))

	node = trie.Get("/a/b/c/d/e/f")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/a/b/c/d")
	assert.Equal(t, node.data, "/a/b/c/d")

	node = trie.Get("/b/c/d/word")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/b/c/d")
	assert.Equal(t, node.data, "/b/c/d")

	node = trie.Get("/b/c/dword")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/b/c")
	assert.Equal(t, node.data, "/b/c")
}

func TestURLTrie_Remove(t *testing.T) {
	var trie = fullTrie()
	var size = trie.size
	var node = trie.Get("/b/just-b")
	assert.Equal(t, node.prefix, "/b")

	trie.Remove("/b")
	// deleting a node doesn't change size if no children
	assert.Equal(t, trie.size, size)
	assert.Nil(t, trie.Get("/b/just-b"))
	node = trie.Get("/b/c/sub-still-here")
	assert.Equal(t, node.prefix, "/b/c")

	node = trie.Get("/a/b/c/d/word")
	assert.Equal(t, node.prefix, "/a/b/c/d")
	var b = trie.branches["a"].branches["b"]
	assert.Equal(t, b.size, 3)
	trie.Remove("/a/b/c/d")
	assert.Equal(t, b.size, 2)
	assert.Nil(t, b.branches["c"])

	trie.Remove("/")
	node = trie.Get("/")
	assert.Nil(t, node)
}

func TestURLTrie_subPaths(t *testing.T) {
	var trie = NewURLTrie("")
	trie.Add("/", "/")

	var node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/")

	// add /prefix/sub/tree
	trie.Add("/prefix/sub/tree", -1)

	// which shouldn't change the results for /prefix and /prefix/sub
	node = trie.Get("/prefix")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/")

	node = trie.Get("/prefix/sub/tree")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/prefix/sub/tree")

	// add /prefix, and run one more time
	trie.Add("/prefix", -1)

	node = trie.Get("/prefix")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/prefix")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/prefix")

	node = trie.Get("/prefix/sub/tree")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/prefix/sub/tree")
}

func TestURLTrie_removeFirstLeafNotRemoveRoot(t *testing.T) {
	var trie = NewURLTrie("")
	trie.Add("/", "/")

	var node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/")

	trie.Add("/prefix", "/prefix")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/prefix")

	trie.Remove("/prefix/")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, node.prefix, "/")
}
