package lib

import (
	"io"
	"log/slog"
)

// Colors
const (
	Reset       = "\033[0m"
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Blue        = "\033[34m"
	Magenta     = "\033[35m"
	Cyan        = "\033[36m"
	White       = "\033[37m"
	BlueBold    = "\033[34;1m"
	MagentaBold = "\033[35;1m"
	RedBold     = "\033[31;1m"
	YellowBold  = "\033[33;1m"
)

func InitLogger(w io.Writer, level slog.Leveler) {
	log := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
}

func ParseLevel(s string) (slog.Leveler, error) {
	var level slog.Level
	err := level.UnmarshalText([]byte(s))
	return level, err
}
