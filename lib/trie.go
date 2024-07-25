package lib

import (
	"regexp"
	"slices"
	"strings"
)

var (
	slashesExp = regexp.MustCompile("^/+|/+$")
)

// trimPrefix cleanup prefix form: /foo/bar
func trimPrefix(prefix string) string {
	// ensure prefix starts with /
	if len(prefix) == 0 {
		return "/"
	}
	if prefix[0] != '/' {
		prefix = "/" + prefix
	}
	// ensure prefix *doesn't* end with / (unless it's exactly /)
	if len(prefix) > 1 && prefix[len(prefix)-1] == '/' {
		// just trim last /, skip strings.Clone
		prefix = prefix[:len(prefix)-1]
	}

	return prefix
}

// stringToPath turn a /prefix/string/ into ['prefix', 'string'].
// Returns nil if empty parts
func stringToPath(s string) []string {
	bytes := slashesExp.ReplaceAll([]byte(s), []byte(""))
	if len(bytes) == 0 {
		return nil
	}
	return strings.Split(string(bytes), "/")
}

// URLTrie is not thread-safe, make sure to lock it if using it in a concurrent way.
type URLTrie struct {
	prefix       string
	branches     map[string]*URLTrie
	size         int
	data         any
	LastActivity int64
}

func NewURLTrie(prefix string) *URLTrie {
	return &URLTrie{
		prefix:   trimPrefix(prefix),
		branches: make(map[string]*URLTrie),
	}
}

func toPathParts(path any) []string {
	var pathParts []string
	if pathStr, pathIsStr := path.(string); pathIsStr {
		pathParts = stringToPath(pathStr)
	} else {
		pathParts, _ = path.([]string)
	}
	return pathParts
}

// Add data to a node in the trie at path
func (trie *URLTrie) Add(path any, data any) {
	pathParts := toPathParts(path)
	if len(pathParts) == 0 {
		trie.data = data
		return
	}
	prefix, rest := pathParts[0], slices.Clone(pathParts[1:])
	if _, ok := trie.branches[prefix]; !ok {
		// join with /, and handle the fact that only root ends with '/'
		var curPrefix string
		if len(trie.prefix) == 1 {
			curPrefix = trie.prefix
		} else {
			curPrefix = trie.prefix + "/"
		}
		trie.branches[prefix] = NewURLTrie(curPrefix + prefix)
		trie.size += 1
	}
	trie.branches[prefix].Add(rest, data)
}

// Remove `path` from the trie
func (trie *URLTrie) Remove(path any) {
	pathParts := toPathParts(path)
	if len(pathParts) == 0 {
		// allow deleting root
		trie.data = nil
		return
	}
	prefix, rest := pathParts[0], pathParts[1:]
	child, exist := trie.branches[prefix]
	if !exist {
		// Requested node doesn't exist, consider it already removed.
		return
	}
	child.Remove(rest)
	if child.size == 0 && child.data == nil {
		delete(trie.branches, prefix)
		trie.size -= 1
	}
}

// Get the data stored at a matching prefix
// returns: {prefix: "/the/matching/prefix", data: <whatever was stored by add>}
func (trie *URLTrie) Get(path any) *URLTrie {
	// if I have data, return me, otherwise return nil
	var me *URLTrie
	if trie.data != nil {
		me = trie
	}

	pathParts := toPathParts(path)
	if len(pathParts) == 0 {
		// exact match, it's definitely me!
		return me
	}
	prefix, rest := pathParts[0], pathParts[1:]
	child, exist := trie.branches[prefix]
	if !exist {
		// prefix matches, and I don't have any more specific children
		return me
	}
	// I match and I have a more specific child that matches.
	// That *does not* mean that I have a more specific *leaf* that matches.
	node := child.Get(rest)
	if node != nil {
		// found a more specific leaf
		return node
	} else {
		// I'm still the most specific match
		return me
	}
}
