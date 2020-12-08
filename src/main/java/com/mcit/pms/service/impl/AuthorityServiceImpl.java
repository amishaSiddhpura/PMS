package com.mcit.pms.service.impl;

import com.mcit.pms.dao.AuthorityDao;
import com.mcit.pms.model.Authority;
import com.mcit.pms.service.AuthorityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service
public class AuthorityServiceImpl implements AuthorityService {

    @Autowired
    AuthorityDao authorityDao;

    @Override
    public void insertAuthorityOfUser(Authority authority) {
        authorityDao.insertAuthorityOfUser(authority);
    }

    @Override
    public void updateUser(Authority authority) {
        authorityDao.updateAuthority(authority);
    }
}
