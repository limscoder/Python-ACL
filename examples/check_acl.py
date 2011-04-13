import acl

if __name__ == '__main__':
    # Build ACL from xml config file
    acl = acl.Acl()
    acl.build_acl('permissions.xml')
 
    assert(acl.check_access('manager', 'time_card', 'write'))
    assert(acl.check_acces('manager', 'time_card', 'approve'))
    assert(acl.check_access('employee', 'time_card', 'write'))
    assert(acl.check_access('employess', 'time_card', 'approve') is False)
