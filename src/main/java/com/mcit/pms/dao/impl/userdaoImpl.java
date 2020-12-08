package com.mcit.pms.dao.impl;

import com.mcit.pms.dao.UserDao;
import com.mcit.pms.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Repository
public class userdaoImpl extends JdbcDaoSupport implements UserDao {

    @Autowired
    DataSource dataSource;

    @PostConstruct
    private void initialize(){
        setDataSource(dataSource);
    }

    @Override
    public void insertUser(User user) {
        String sql = "INSERT INTO users " +
                "(username, password,enabled) VALUES (?,?,1)" ;
         getJdbcTemplate().update(sql, new Object[]{
                user.getUsername(), user.getPassword()
        });
    }

    @Override
    public List<User> getAllUsers() {
        String sql = "SELECT u.id,u.username as username, u.enabled as enable, a.authority as authority FROM users u inner join authorities a on a.username = u.username";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql);

        List<User> result = new ArrayList<User>();
        for(Map<String, Object> row:rows){
            User user = new User();
            user.setId((Integer)row.get("id"));
            user.setUsername((String)row.get("username"));
            user.setRole((String)row.get("authority"));
            user.setEnable((Boolean) row.get("enable"));
            result.add(user);
        }

        return result;
    }

    @Override
    public boolean checkUserName(String username) {
        String sql = "SELECT count from users where username=?";

        return false;
    }

    @Override
    public User findByUserName(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql, username);

        for(Map<String, Object> row:rows){
            User user = new User();
            user.setId((Integer)row.get("id"));
            user.setUsername((String) row.get("username"));
            return user;
        }
        return new User();
    }

    @Override
    public void updateUser(User user) {
        getJdbcTemplate().execute("update users set username='"+user.getUsername()+"' where id="+ user.getId());
    }

    @Override
    public void deleteUser(Integer id) {
        getJdbcTemplate().execute("delete from authorities where userid ="+ id);
        getJdbcTemplate().execute("delete from users where id ="+ id);
    }

    @Override
    public User getByUser(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        return (User) getJdbcTemplate().queryForObject(sql, new Object[]{username}, new RowMapper<User>(){
            @Override
            public User mapRow(ResultSet rs, int rwNumber) throws SQLException {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEnable(rs.getBoolean("enabled"));
                return user;
            }
        });
    }

    @Override
    public User getById(Integer id) {
        String sql = "SELECT * FROM users WHERE id = ?";
        return (User) getJdbcTemplate().queryForObject(sql, new Object[]{id}, new RowMapper<User>(){
            @Override
            public User mapRow(ResultSet rs, int rwNumber) throws SQLException {
                User user = new User();
                user.setUsername(rs.getString("username"));
                user.setEnable(rs.getBoolean("enabled"));
                return user;
            }
        });
    }

    @Override
    public List<User> getunAssignedUsers(Integer projectID) {
        String sql = "select * from users u inner join authorities a on a.userid = u.id where u.id not in (select member from projectmember where projectid = ?) and a.authority in ('ROLE_MEMBER','ROLE_LEADER');";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql, projectID);

        List<User> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            User user = new User();
            user.setId((Integer)row.get("id"));
            user.setUsername((String) row.get("username"));
            result.add(user);
        }

        return result;
    }

    @Override
    public Collection<? extends User> getAssignedUsers(Integer id) {
        String sql = "select * from users u  where u.id in (select distinct member from projectmember where projectid = ?);";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql, id);

        List<User> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            User user = new User();
            user.setId((Integer)row.get("id"));
            user.setUsername((String) row.get("username"));
            result.add(user);
        }

        return result;
    }

    @Override
    public List<User> getMembers() {
        String sql = "select u.id,u.username from users u inner join authorities a on a.userid = u.id where a.authority = 'ROLE_MEMBER';";
        List<Map<String, Object>> rows = getJdbcTemplate().queryForList(sql);

        List<User> result = new ArrayList<>();
        for(Map<String, Object> row:rows){
            User user = new User();
            user.setId((Integer)row.get("id"));
            user.setUsername((String) row.get("username"));
            result.add(user);
        }

        return result;
    }
}
