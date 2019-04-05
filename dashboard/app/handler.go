// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/html"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/user"
)

// This file contains common middleware for UI handlers (auth, html templates, etc).

type contextHandler func(c context.Context, w http.ResponseWriter, r *http.Request) error

func handlerWrapper(fn contextHandler) http.Handler {
	return handleContext(handleAuth(fn))
}

func handleContext(fn contextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := fn(c, w, r); err != nil {
			hdr, _ := commonHeader(c, r, w, "")
			data := &struct {
				Header *uiHeader
				Error  string
			}{
				Header: hdr,
				Error:  err.Error(),
			}
			if err == ErrAccess {
				w.WriteHeader(http.StatusForbidden)
				err1 := templates.ExecuteTemplate(w, "forbidden.html", data)
				if err1 != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			if _, dontlog := err.(ErrDontLog); !dontlog {
				log.Errorf(c, "%v", err)
			}
			w.WriteHeader(http.StatusInternalServerError)
			if err1 := templates.ExecuteTemplate(w, "error.html", data); err1 != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

type ErrDontLog error

func handleAuth(fn contextHandler) contextHandler {
	return func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := checkAccessLevel(c, r, config.AccessLevel); err != nil {
			return err
		}
		return fn(c, w, r)
	}
}

func serveTemplate(w http.ResponseWriter, name string, data interface{}) error {
	buf := new(bytes.Buffer)
	if err := templates.ExecuteTemplate(buf, name, data); err != nil {
		return err
	}
	w.Write(buf.Bytes())
	return nil
}

type uiHeader struct {
	Admin               bool
	LoginLink           string
	AnalyticsTrackingID string
	Subpage             string
	Namespace           string
	Namespaces          []uiNamespace
	Redirects           []uiRedirect
}

type uiNamespace struct {
	Name    string
	Caption string
}

type uiRedirect struct {
	From string
	To   string
}

type cookieData struct {
	Namespace string `json:"namespace"`
}

func commonHeader(c context.Context, r *http.Request, w http.ResponseWriter, ns string) (*uiHeader, bool) {
	accessLevel := accessLevel(c, r)
	if ns == "" {
		ns = strings.ToLower(r.URL.Path)
		if ns != "" && ns[0] == '/' {
			ns = ns[1:]
		}
		if pos := strings.IndexByte(ns, '/'); pos != -1 {
			ns = ns[:pos]
		}
	}
	//!!! check namespace access level and return ErrAccess
	h := &uiHeader{
		Admin:               accessLevel == AccessAdmin,
		AnalyticsTrackingID: config.AnalyticsTrackingID,
	}
	found := false
	for ns1, cfg := range config.Namespaces {
		if accessLevel < cfg.AccessLevel {
			continue
		}
		if ns1 == ns {
			found = true
		}
		h.Namespaces = append(h.Namespaces, uiNamespace{
			Name:    ns1,
			Caption: cfg.DisplayTitle,
		})
		// This handles redirects from old URL scheme to new scheme.
		// This this should be removed at some point (Apr 5, 2019).
		// Also see handling of "fixed" parameter in handleMain.
		h.Redirects = append(h.Redirects, uiRedirect{
			From: "#" + ns1,
			To:   "/" + ns1,
		})
		fragments := []string{"managers", "open", "pending"}
		for _, reporting := range cfg.Reporting {
			if !reporting.moderation || reporting.AccessLevel < accessLevel {
				continue
			}
			fragments = append(fragments, reporting.Name)
		}
		for _, frag := range fragments {
			h.Redirects = append(h.Redirects, uiRedirect{
				From: "#" + ns1 + "-" + frag,
				To:   "/" + ns1 + "#" + frag,
			})
		}
	}
	sort.Slice(h.Namespaces, func(i, j int) bool {
		return h.Namespaces[i].Caption < h.Namespaces[j].Caption
	})
	cookie := decodeCookie(r)
	if !found {
		ns = config.DefaultNamespace
		if cfg := config.Namespaces[cookie.Namespace]; cfg != nil && cfg.AccessLevel <= accessLevel {
			ns = cookie.Namespace
		}
		if accessLevel == AccessAdmin {
			ns = "admin"
		}
	}
	h.Namespace = ns
	cookie.Namespace = ns
	encodeCookie(w, cookie)
	if user.Current(c) == nil {
		h.LoginLink, _ = user.LoginURL(c, r.URL.String())
	}
	return h, !found
}

const cookieName = "syzkaller"

func decodeCookie(r *http.Request) *cookieData {
	cd := new(cookieData)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return cd
	}
	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return cd
	}
	json.Unmarshal(decoded, cd)
	return cd
}

func encodeCookie(w http.ResponseWriter, cd *cookieData) {
	data, err := json.Marshal(cd)
	if err != nil {
		return
	}
	cookie := &http.Cookie{
		Name:  cookieName,
		Value: base64.StdEncoding.EncodeToString(data),
	}
	http.SetCookie(w, cookie)
}

var templates = html.CreateGlob("*.html")
