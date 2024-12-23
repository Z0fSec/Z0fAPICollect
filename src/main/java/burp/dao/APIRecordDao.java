package burp.dao;

import burp.bean.APIRecordBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;


public class APIRecordDao {

    // 删除配置
    public static void deleteAPI(String url) {
        String sql = "delete from api_record where url = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, url);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据host删除API记录
    public static void deleteAPIRecordByHost(String host) {
        String sql = "delete from api_record where host = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, host);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据host删除API记录
    public static void deleteAPIRecordById(Integer id) {
        String sql = "delete from api_record where id = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据类型更新配置
    public static void updateAPIRecord(APIRecordBean api_record) {
        String sql = "update api_record set method = ?, url = ?, request = ?, response = ? where id = ? ";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, api_record.getMethod());
            ps.setString(2, api_record.getUrl());
            ps.setString(3, api_record.getRequest());
            ps.setString(4, api_record.getResponse());
            ps.setInt(5, api_record.getId());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 保存API记录
    public static void saveAPIRecord(APIRecordBean api_record) {
        String sql = "INSERT OR REPLACE INTO api_record (method , url , request , response ) VALUES (?, ?, ?,?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, api_record.getMethod());
            ps.setString(2, api_record.getUrl());
            ps.setString(3, api_record.getRequest());
            ps.setString(4, api_record.getResponse());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 获取API记录列表
    public static List<APIRecordBean> getAPIRecords() {
        List<APIRecordBean> api_records = new ArrayList<>();
        String sql = "select * from api_record";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                APIRecordBean api_record = new APIRecordBean();
                api_record.setId(resultSet.getInt("id"));
                api_record.setMethod(resultSet.getString("method"));
                api_record.setUrl(resultSet.getString("url"));
                api_record.setRequest(resultSet.getString("request"));
                api_record.setRequest(resultSet.getString("response"));
                api_records.add(api_record);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return api_records;
    }

}
