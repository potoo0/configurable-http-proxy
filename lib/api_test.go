package lib

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_parseTime(t *testing.T) {

	var testCases = []struct {
		raw string

		year  int
		month int
		day   int

		hour        int
		minute      int
		second      int
		milliSecond int

		zone float64
	}{
		{
			raw:  "2024-07-25T20:40:11.502+0100",
			year: 2024, month: 7, day: 25,
			hour: 20, minute: 40, second: 11, milliSecond: 502,
			zone: 1,
		},
		{
			raw:  "2024-07-25T20:40:11.502+0800",
			year: 2024, month: 7, day: 25,
			hour: 20, minute: 40, second: 11, milliSecond: 502,
			zone: 8,
		},
		{
			raw:  "2024-07-25T20:40:11.502-0100",
			year: 2024, month: 7, day: 25,
			hour: 20, minute: 40, second: 11, milliSecond: 502,
			zone: -1,
		},
		{
			raw:  "2024-07-25T20:40:11+0800",
			year: 2024, month: 7, day: 25,
			hour: 20, minute: 40, second: 11,
			zone: 8,
		},
		{
			raw:  "2024-07-25T20:40:11.123+08:00",
			year: 2024, month: 7, day: 25,
			hour: 20, minute: 40, second: 11, milliSecond: 123,
			zone: 8,
		},
		// cannot parse ...
		//{
		//	raw:  "2024-07-25T20:40:11",
		//	year: 2024, month: 7, day: 25,
		//	hour: 20, minute: 40, second: 11,
		//},
		//{
		//	raw:  "2024-07-25T20:40",
		//	year: 2024, month: 7, day: 25,
		//	hour: 20, minute: 40,
		//},
		//{
		//	raw:  "2024-07-25",
		//	year: 2024, month: 7, day: 25,
		//	hour: 20, minute: 40,
		//},
		//{
		//	raw:  "2024",
		//	year: 2024,
		//},
	}

	for _, c := range testCases {
		parsed, err := parseTime(c.raw)
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, c.year, parsed.Year(), "year mismatch")
		assert.Equal(t, time.Month(c.month), parsed.Month(), "month mismatch")
		assert.Equal(t, c.day, parsed.Day(), "day mismatch")
		assert.Equal(t, c.hour, parsed.Hour(), "hour mismatch")
		assert.Equal(t, c.minute, parsed.Minute(), "minute mismatch")
		assert.Equal(t, c.second, parsed.Second(), "second mismatch")
		assert.Equal(t, c.milliSecond*1e6, parsed.Nanosecond(), "millisecond mismatch")
		_, z := parsed.Zone()
		assert.Equal(t, c.zone, float64(z)/3600, "zone mismatch")
	}
}
