package burp.utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DbUtils {
    public static String DB_NAME = "Z0fAPICollect.db";
    public static String PROJECT_PATH = System.getProperty("user.home") + "/.z0fsec/Z0fAPICollect/";
    public static String DB_PATH = System.getProperty("user.home") + "/.z0fsec/Z0fAPICollect/" + DB_NAME;
    public static String DB_URL = "jdbc:sqlite:" + DB_PATH;
    public static String DB_DRIVER = "org.sqlite.JDBC";

    static {
        try {
            Class.forName(DB_DRIVER);
        } catch (ClassNotFoundException e) {
            Utils.stderr.println(e.getMessage());
        }
        // 判断文件夹是否存在 若不存在则先创建
        Path path = Paths.get(PROJECT_PATH);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
                Utils.stdout.println("init filepath success");
            } catch (Exception e) {
                Utils.stderr.println("创建文件夹失败");
            }
            // 创建数据库
            create();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // 如果数据库不存在，创建数据库
    public static void create() {
        // 判断数据库是否存在
        try {

            Connection connection = DriverManager.getConnection(DB_URL);

            List<String> sqls = new ArrayList<>();

            // zac_config table
            sqls.add("CREATE TABLE IF NOT EXISTS 'zac_config' ('id' INTEGER, 'type' TEXT, 'value' TEXT, PRIMARY KEY ('id'))");

            sqls.add("CREATE TABLE IF NOT EXISTS 'api_record' ('id' INTEGER, 'method' TEXT, 'url' TEXT,'request' TEXT,'response' TEXT, PRIMARY KEY ('id'))");

            // Insert zac_config data
            sqls.add("INSERT INTO 'zac_config' VALUES (14, 'header', 'User-Agent')");
            sqls.add("INSERT INTO 'zac_config' VALUES (15, 'header', 'Cookie')");
            sqls.add("INSERT INTO 'zac_config' VALUES (21, 'domain', 'www.baidu.com')");
            sqls.add("INSERT INTO 'zac_config' VALUES (23, 'payload', '0''XOR(if(1,sleep(6),0))XOR''Z')");
            for (String sql : sqls) {
                Statement statement = connection.createStatement();
                statement.execute(sql);
                statement.close();
            }
            Utils.stdout.println("init db success");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void close(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet) {
        try {
            if (connection != null) {
                connection.close();
            }
            if (preparedStatement != null) {
                preparedStatement.close();
            }
            if (resultSet != null) {
                resultSet.close();
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

}