/*
 Navicat Premium Data Transfer

 Source Server         : local_MySql
 Source Server Type    : MySQL
 Source Server Version : 50647
 Source Host           : 192.168.2.104:3306
 Source Schema         : DZBD

 Target Server Type    : MySQL
 Target Server Version : 50647
 File Encoding         : 65001

 Date: 25/04/2020 14:15:27
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for tb_functions
-- ----------------------------
DROP TABLE IF EXISTS `tb_functions`;
CREATE TABLE `tb_functions`  (
  `func_id` int(10) NOT NULL,
  `func_name` varchar(30) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `func_url` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `func_code` varchar(30) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `parent_id` int(20) NULL DEFAULT NULL,
  `func_type` int(10) NULL DEFAULT NULL,
  `status` int(5) NULL DEFAULT NULL,
  `sort_num` int(20) NULL DEFAULT NULL,
  `create_time` timestamp(0) NULL DEFAULT NULL,
  `update_time` timestamp(0) NULL DEFAULT NULL,
  PRIMARY KEY (`func_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_functions
-- ----------------------------
INSERT INTO `tb_functions` VALUES (1, '添加', NULL, 'function:add', NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO `tb_functions` VALUES (2, '修改', NULL, 'function:update', NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO `tb_functions` VALUES (3, '删除', NULL, 'function:delete', NULL, NULL, NULL, NULL, NULL, NULL);

-- ----------------------------
-- Table structure for tb_role_function
-- ----------------------------
DROP TABLE IF EXISTS `tb_role_function`;
CREATE TABLE `tb_role_function`  (
  `role_id` int(10) NOT NULL,
  `func_id` int(10) NOT NULL,
  PRIMARY KEY (`role_id`, `func_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_role_function
-- ----------------------------
INSERT INTO `tb_role_function` VALUES (1, 1);
INSERT INTO `tb_role_function` VALUES (1, 2);

-- ----------------------------
-- Table structure for tb_roles
-- ----------------------------
DROP TABLE IF EXISTS `tb_roles`;
CREATE TABLE `tb_roles`  (
  `role_id` int(10) NOT NULL,
  `role_name` varchar(30) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `note` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `system` bit(10) NULL DEFAULT NULL,
  `status` int(6) NULL DEFAULT NULL,
  `create_time` timestamp(0) NULL DEFAULT NULL,
  `update_time` timestamp(0) NULL DEFAULT NULL,
  PRIMARY KEY (`role_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_roles
-- ----------------------------
INSERT INTO `tb_roles` VALUES (1, '管理员', 'root', NULL, NULL, NULL, NULL);

-- ----------------------------
-- Table structure for tb_user_role
-- ----------------------------
DROP TABLE IF EXISTS `tb_user_role`;
CREATE TABLE `tb_user_role`  (
  `user_id` int(10) NOT NULL,
  `role_id` int(10) NOT NULL,
  PRIMARY KEY (`user_id`, `role_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_user_role
-- ----------------------------
INSERT INTO `tb_user_role` VALUES (2, 1);

-- ----------------------------
-- Table structure for tb_users
-- ----------------------------
DROP TABLE IF EXISTS `tb_users`;
CREATE TABLE `tb_users`  (
  `user_id` int(10) NOT NULL,
  `user_name` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `password` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `phone` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `email` varchar(30) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `salt` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `status` int(10) NULL DEFAULT NULL,
  `note` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `create_time` timestamp(0) NULL DEFAULT NULL,
  `update_time` timestamp(0) NULL DEFAULT NULL,
  PRIMARY KEY (`user_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Records of tb_users
-- ----------------------------
INSERT INTO `tb_users` VALUES (1, 'test', '098f6bcd4621d373cade4e832627b4f6', NULL, NULL, '', NULL, NULL, NULL, NULL);
INSERT INTO `tb_users` VALUES (2, 'admin', 'b9d11b3be25f5a1a7dc8ca04cd310b28', NULL, NULL, '123456', NULL, NULL, NULL, NULL);

SET FOREIGN_KEY_CHECKS = 1;
