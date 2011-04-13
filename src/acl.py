"""Role based access control list."""

from xml.dom.minidom import parse
 
class AccessError(Exception):
    pass
 
class Resource(object):
    """A Resource is an object that can be accessed by a Role."""

    def __init__(self, name=''):
        self.name = name
        self._privileges = {}
 
    def set_privilege(self, privilege, allowed=True):
        self._privileges[privilege] = allowed
 
    def has_access(self, privilege):
        if privilege in self._privileges:
            return self._privileges[privilege]
        return False
     
    def __str__(self):
        rpr = self.name + ': '
        for privilege, access in self._privileges.iteritems():
            rpr += "%s:%s " % (privilege, access)
        return rpr
 
class Role(object):
    def __init__(self, name=''):
        """An Acl role has access to resources with specific privileges."""

        self.name = name
        self._parents = {}
        self._resources = {}
 
    def set_parent(self, parent):
        self._parents[parent.name] = parent
 
    def set_resource(self, resource):
        self._resources[resource.name] = resource
 
    def has_access(self, attr_name, privilege):
        if attr_name in self._resources:
            if self._resources[attr_name].has_access(privilege):
                return True
 
        for parent in self._parents.values():
            if parent.has_access(attr_name, privilege):
                return True
 
        return False
     
    def __str__(self):
        rpr = self.name + ":\n"
        rpr += "parents:\n"
        for parent in self._parents.keys():
            rpr += "\t%s\n" % parent
        rpr += "resources:\n"
        for resource in self._resources.values():
            rpr += "\t%s\n" % resource.describe()
        return rpr
 
class Acl(object):
    """
    Manages roles and resources.
     
    Singleton class.
    """
 
    class __impl:
        """Implementation of the singleton interface"""
         
        def __init__(self):
            self._acl = {}
 
        def set_role(self, role):
            self._acl[role.name] = role
             
        def check_access(self, role_name, resource, privilege):
            """Check whether a role has access to a resource or not."""
 
            if not role_name in self._acl:
                raise AccessError('Role does not exist.')
            return self._acl[role_name].has_access(resource, privilege)
 
        def build_acl(self, file): 
            """Build acl from an XML file."""
 
            self._acl = {}
            roles_to_create = {}
            dom = parse(file)
             
            # Find roles to create
            roles_nodes = dom.getElementsByTagName('roleSet')
            for roles_node in roles_nodes:
                role_nodes = roles_node.getElementsByTagName('role')
                for role_node in role_nodes:
                    name_nodes = role_node.getElementsByTagName('name')
                    parent_nodes = role_node.getElementsByTagName('inheritFrom')
                    role_name = name_nodes[0].childNodes[0].data
                    roles_to_create[role_name] = []
 
                    # Find role parents
                    for parent_node in parent_nodes:
                        roles_to_create[role_name].append(parent_node.childNodes[0].data)
 
            # build inheritence chain
            for role, parents in roles_to_create.iteritems():
                self.set_role(self._create_role(role, roles_to_create))
 
            # assign permissions
            permissions = dom.getElementsByTagName('permissions')
            for permissions_node in permissions:
                permission_nodes = permissions_node.getElementsByTagName('permission')
                for permission_node in permission_nodes:
                    resource_nodes = permission_node.getElementsByTagName('resource')
                    role_nodes = permission_node.getElementsByTagName('role')
                    privilege_nodes = permission_node.getElementsByTagName('privilege')
 
                    for resource_node in resource_nodes:
                       resource = Resource()
                       resource.name = resource_node.childNodes[0].data
                       for privilege_node in privilege_nodes:
                           resource.set_privilege(privilege_node.childNodes[0].data)
 
                       for role_node in role_nodes:
                           try:
                               role = self._acl[role_node.childNodes[0].data]
                           except:
                               raise AccessError('Role in permission is not defined.')
 
                           role.set_resource(resource)
 
        def _create_role(self, role_name, roles_to_create):
            """Recursively create parent roles and then create child role."""
             
            if role_name in self._acl:
                role = self._acl[role_name]
            else:
                role = Role()
                role.name = role_name
                 
            for parent_name in roles_to_create[role_name]:
                if parent_name in self._acl:
                    parent = self._acl[parent_name]
                else:
                    parent = self._create_role(parent_name, roles_to_create)
                    self.set_role(parent)
                role.set_parent(parent)
            return role
         
        def __str__(self):
            rpr = ''
            for role in self._acl.values():
                rpr += '----------\n'
                rpr += role.describe()
            return rpr
 
    __instance = None
 
    def __init__(self):
        """ Create singleton instance """
         
        # Check whether an instance already exists.
        # If not, create it.
        if Acl.__instance is None:
            Acl.__instance = Acl.__impl()
 
        self.__dict__['_Acl__instance'] = Acl.__instance
 
    def __getattr__(self, attr):
        """ Delegate get access to implementation """
 
        return getattr(self.__instance, attr)
 
    def __setattr__(self, attr, val):
        """ Delegate set access to implementation """
 
        return setattr(self.__instance, attr, val)
