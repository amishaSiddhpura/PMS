package com.mcit.pms.dao.impl;

import com.mcit.pms.dao.AuthorityDao;
import com.mcit.pms.model.Authority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

@Repository
public class AuthorityDaoImpl extends JdbcDaoSupport implements AuthorityDao {

    @Autowired
    DataSource dataSource;

    @PostConstruct
    private void initialize(){
        setDataSource(dataSource);
    }


    @Override
    public void insertAuthorityOfUser(Authority authority) {
        String sql = "INSERT INTO authorities " +
                "(userid,username,authority) VALUES (?, ?,?)" ;
        getJdbcTemplate().update(sql, new Object[]{
                authority.getUserID(),authority.getUserName(), authority.getAuthority()
        });
    }

    @Override
    public void updateAuthority(Authority authority) {
        String sql = "update authorities set username=?,authority=? where userid=?";
        getJdbcTemplate().update(sql,authority.getUserName(),authority.getAuthority(),authority.getUserID());
    }
}
