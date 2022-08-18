sessiondata = {
    "id": 34,
    "pageentry": "welcome.html"
}

from GlobalSessionContainer import GlobalSessionContainer

session = GlobalSessionContainer(sessiondata)

session.set("testvalue", "red")
print(sessiondata)

session.remove("pageentry")
print(sessiondata)