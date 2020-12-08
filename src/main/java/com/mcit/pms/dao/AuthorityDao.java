package com.mcit.pms.dao;

import com.mcit.pms.model.Authority;

public interface AuthorityDao {
    void insertAuthorityOfUser(Authority authority);

    void updateAuthority(Authority authority);
}
