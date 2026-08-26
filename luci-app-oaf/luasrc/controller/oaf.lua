module("luci.controller.oaf", package.seeall)

function index()
    entry({"admin", "services", "oaf"}, firstchild(), _("Parental Control"), 20).dependent = true
end
