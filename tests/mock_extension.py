from laurelin.ldap import BaseLaurelinExtension, BaseLaurelinLDAPExtension, BaseLaurelinLDAPObjectExtension


class LaurelinExtension(BaseLaurelinExtension):
    NAME = 'mock_ext'


class LaurelinLDAPExtension(BaseLaurelinLDAPExtension):
    def foo(self):
        return 'foo'


class LaurelinLDAPObjectExtension(BaseLaurelinLDAPObjectExtension):
    def bar(self):
        return 'bar'
