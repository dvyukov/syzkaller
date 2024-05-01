// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package flatrpc

import "strconv"

type RequestFlag uint64

const (
	RequestFlagIsBinary     RequestFlag = 1
	RequestFlagNewSignal    RequestFlag = 2
	RequestFlagResetState   RequestFlag = 4
	RequestFlagReturnOutput RequestFlag = 8
	RequestFlagReturnError  RequestFlag = 16
)

var EnumNamesRequestFlag = map[RequestFlag]string{
	RequestFlagIsBinary:     "IsBinary",
	RequestFlagNewSignal:    "NewSignal",
	RequestFlagResetState:   "ResetState",
	RequestFlagReturnOutput: "ReturnOutput",
	RequestFlagReturnError:  "ReturnError",
}

var EnumValuesRequestFlag = map[string]RequestFlag{
	"IsBinary":     RequestFlagIsBinary,
	"NewSignal":    RequestFlagNewSignal,
	"ResetState":   RequestFlagResetState,
	"ReturnOutput": RequestFlagReturnOutput,
	"ReturnError":  RequestFlagReturnError,
}

func (v RequestFlag) String() string {
	if s, ok := EnumNamesRequestFlag[v]; ok {
		return s
	}
	return "RequestFlag(" + strconv.FormatInt(int64(v), 10) + ")"
}
