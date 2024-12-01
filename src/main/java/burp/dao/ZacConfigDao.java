package burp.dao;

import burp.bean.ZacConfigBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ZacConfigDao {

    // 保存
    public static void saveConfig(ZacConfigBean zacConfigBean) {
        String sql = "INSERT OR REPLACE INTO zac_config (type, value) VALUES (?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, zacConfigBean.getType());
            ps.setString(2, zacConfigBean.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 更新
    public static void updateConfig(ZacConfigBean zacConfigBean) {
        String sql = "update zac_config set value = ? where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, zacConfigBean.getValue());
            ps.setString(2, zacConfigBean.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据type获取多个
    public static List<ZacConfigBean> getConfigListsByType(String type) {
        List<ZacConfigBean> sqlLists = new ArrayList<>();
        String routesql = "select * from zac_config where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(routesql);
            ps.setString(1, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                ZacConfigBean zacConfigBean = new ZacConfigBean();
                zacConfigBean.setId(resultSet.getInt("id"));
                zacConfigBean.setType(resultSet.getString("type"));
                zacConfigBean.setValue(resultSet.getString("value"));
                sqlLists.add(zacConfigBean);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return sqlLists;
    }

    // 根据type删除
    public static void deleteSqlByType(String type) {
        String sql = "delete from zac_config where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据type和value删除
    public static void deleteConfigByTypeAndValue(String type, String value) {
        String sql = "delete from zac_config where type = ? and value = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            ps.setString(2, value);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
