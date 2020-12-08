package com.mcit.pms.model;

import org.hibernate.validator.constraints.NotEmpty;

public class Authority {

    @NotEmpty(message = "Username is required")
    private String userName;

    @NotEmpty(message = "Authority is required")
    private String authority;

    @NotEmpty(message = "First name is required")
    private Integer userID;

    public Authority(Integer id,String userName, String authority) {
        this.userName = userName;
        this.authority = authority;
        this.userID = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public Integer getUserID() {
        return userID;
    }

    public void setUserID(Integer userID) {
        this.userID = userID;
    }
}
