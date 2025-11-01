package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, "/", trie.prefix)
	assert.Equal(t, 0, trie.size)
	assert.Nil(t, trie.data)
	assert.Empty(t, trie.branches)

	trie = NewURLTrie("/foo")
	assert.Equal(t, "/foo", trie.prefix)
	assert.Equal(t, 0, trie.size)
	assert.Nil(t, trie.data)
	assert.Empty(t, trie.branches)
}

func TestURLTrie_Root(t *testing.T) {
	trie := NewURLTrie("/")
	trie.Add("/", -1)

	node := trie.Get("/1/etc/etc/")
	assert.NotNil(t, node)
	assert.Equal(t, "/", trie.prefix)
	assert.Equal(t, -1, trie.data)

	node = trie.Get("/")
	assert.NotNil(t, node)
	assert.Equal(t, "/", trie.prefix)
	assert.Equal(t, -1, trie.data)

	node = trie.Get("")
	assert.NotNil(t, node)
	assert.Equal(t, "/", trie.prefix)
	assert.Equal(t, -1, trie.data)
}

func TestURLTrie_Add(t *testing.T) {
	trie := NewURLTrie("")

	trie.Add("foo", 1)
	assert.Equal(t, 1, trie.size)

	assert.Nil(t, trie.data)
	assert.Equal(t, 1, trie.branches["foo"].data)
	assert.Equal(t, 0, trie.branches["foo"].size)

	trie.Add("bar/leaf", 2)
	assert.Equal(t, 2, trie.size)

	bar := trie.branches["bar"]
	assert.Equal(t, "/bar", bar.prefix)
	assert.Equal(t, 1, bar.size)
	assert.Equal(t, 2, bar.branches["leaf"].data)

	trie.Add("/a/b/c/d", 4)
	assert.Equal(t, 3, trie.size)

	a := trie.branches["a"]
	assert.Equal(t, "/a", a.prefix)
	assert.Equal(t, 1, a.size)
	assert.Nil(t, a.data)

	b := a.branches["b"]
	assert.Equal(t, "/a/b", b.prefix)
	assert.Equal(t, 1, b.size)
	assert.Nil(t, b.data)

	c := b.branches["c"]
	assert.Equal(t, "/a/b/c", c.prefix)
	assert.Equal(t, 1, c.size)
	assert.Nil(t, c.data)

	d := c.branches["d"]
	assert.Equal(t, "/a/b/c/d", d.prefix)
	assert.Equal(t, 0, d.size)
	assert.Equal(t, 4, d.data)
}

func TestURLTrie_Get(t *testing.T) {
	trie := fullTrie()
	assert.Nil(t, trie.Get("/not/found"))

	node := trie.Get("/1")
	assert.Equal(t, "/1", node.prefix)
	assert.Equal(t, "/1", node.data)

	node = trie.Get("/1/etc/etc/")
	assert.NotNil(t, node)
	assert.Equal(t, "/1", node.prefix)
	assert.Equal(t, "/1", node.data)

	assert.Nil(t, trie.Get("/a"))
	assert.Nil(t, trie.Get("/a/b/c"))

	node = trie.Get("/a/b/c/d/e/f")
	assert.NotNil(t, node)
	assert.Equal(t, "/a/b/c/d", node.prefix)
	assert.Equal(t, "/a/b/c/d", node.data)

	node = trie.Get("/b/c/d/word")
	assert.NotNil(t, node)
	assert.Equal(t, "/b/c/d", node.prefix)
	assert.Equal(t, "/b/c/d", node.data)

	node = trie.Get("/b/c/dword")
	assert.NotNil(t, node)
	assert.Equal(t, "/b/c", node.prefix)
	assert.Equal(t, "/b/c", node.data)
}

func TestURLTrie_Remove(t *testing.T) {
	trie := fullTrie()
	size := trie.size
	node := trie.Get("/b/just-b")
	assert.Equal(t, "/b", node.prefix)

	trie.Remove("/b")
	// deleting a node doesn't change size if no children
	assert.Equal(t, trie.size, size)
	assert.Nil(t, trie.Get("/b/just-b"))
	node = trie.Get("/b/c/sub-still-here")
	assert.Equal(t, "/b/c", node.prefix)

	node = trie.Get("/a/b/c/d/word")
	assert.Equal(t, "/a/b/c/d", node.prefix)
	b := trie.branches["a"].branches["b"]
	assert.Equal(t, 3, b.size)
	trie.Remove("/a/b/c/d")
	assert.Equal(t, 2, b.size)
	assert.Nil(t, b.branches["c"])

	trie.Remove("/")
	node = trie.Get("/")
	assert.Nil(t, node)
}

func TestURLTrie_subPaths(t *testing.T) {
	trie := NewURLTrie("")
	trie.Add("/", "/")

	node := trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/", node.prefix)

	// add /prefix/sub/tree
	trie.Add("/prefix/sub/tree", -1)

	// which shouldn't change the results for /prefix and /prefix/sub
	node = trie.Get("/prefix")
	assert.NotNil(t, node)
	assert.Equal(t, "/", node.prefix)

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/", node.prefix)

	node = trie.Get("/prefix/sub/tree")
	assert.NotNil(t, node)
	assert.Equal(t, "/prefix/sub/tree", node.prefix)

	// add /prefix, and run one more time
	trie.Add("/prefix", -1)

	node = trie.Get("/prefix")
	assert.NotNil(t, node)
	assert.Equal(t, "/prefix", node.prefix)

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/prefix", node.prefix)

	node = trie.Get("/prefix/sub/tree")
	assert.NotNil(t, node)
	assert.Equal(t, "/prefix/sub/tree", node.prefix)
}

func TestURLTrie_removeFirstLeafNotRemoveRoot(t *testing.T) {
	trie := NewURLTrie("")
	trie.Add("/", "/")

	node := trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/", node.prefix)

	trie.Add("/prefix", "/prefix")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/prefix", node.prefix)

	trie.Remove("/prefix/")

	node = trie.Get("/prefix/sub")
	assert.NotNil(t, node)
	assert.Equal(t, "/", node.prefix)
}
