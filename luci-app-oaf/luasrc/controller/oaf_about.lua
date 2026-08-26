module("luci.controller.oaf_about", package.seeall)

function index()
	entry({"admin", "services", "oaf", "about"}, template("oaf/about"), _("About"), 100).leaf = true
end
