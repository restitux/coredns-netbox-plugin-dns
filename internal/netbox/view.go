package netbox

import (
	"net/netip"
	"net/url"
	"strconv"
)

type Prefix struct {
	ID     int    `json:"id"`
	Prefix string `json:"prefix"`
}

type View struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Prefixes []Prefix `json:"prefixes"`
	Default  bool     `json:"default_view`
}

func (v View) ContainsIP(IP netip.Addr) (bool, error) {
	for _, prefixObj := range v.Prefixes {
		prefix, err := netip.ParsePrefix(prefixObj.Prefix)
		if err != nil {
			return false, err
		}

		if prefix.Contains(IP) {
			return true, nil
		}
	}
	return false, nil
}

func urlViewID(netboxurl *url.URL, id int) *url.URL {
	return netboxurl.JoinPath("views", "/", strconv.Itoa(id), "/")
}

func GetView(requestClient *APIRequestClient, id int) (View, error) {
	requestUrl := urlViewID(requestClient.NetboxURL, id)
	view, err := get[View](requestClient, requestUrl.String())
	if err != nil {
		return View{}, err
	}
	return view, nil
}
