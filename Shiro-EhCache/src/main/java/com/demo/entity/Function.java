package com.demo.entity;

import java.util.Date;

public class Function {
    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.func_id
     *
     * @mbg.generated
     */
    private Integer funcId;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.func_name
     *
     * @mbg.generated
     */
    private String funcName;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.func_url
     *
     * @mbg.generated
     */
    private String funcUrl;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.func_code
     *
     * @mbg.generated
     */
    private String funcCode;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.parent_id
     *
     * @mbg.generated
     */
    private Integer parentId;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.func_type
     *
     * @mbg.generated
     */
    private Integer funcType;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.status
     *
     * @mbg.generated
     */
    private Integer status;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.sort_num
     *
     * @mbg.generated
     */
    private Integer sortNum;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.create_time
     *
     * @mbg.generated
     */
    private Date createTime;

    /**
     *
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column tb_functions.update_time
     *
     * @mbg.generated
     */
    private Date updateTime;

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.func_id
     *
     * @return the value of tb_functions.func_id
     *
     * @mbg.generated
     */
    public Integer getFuncId() {
        return funcId;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.func_id
     *
     * @param funcId the value for tb_functions.func_id
     *
     * @mbg.generated
     */
    public void setFuncId(Integer funcId) {
        this.funcId = funcId;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.func_name
     *
     * @return the value of tb_functions.func_name
     *
     * @mbg.generated
     */
    public String getFuncName() {
        return funcName;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.func_name
     *
     * @param funcName the value for tb_functions.func_name
     *
     * @mbg.generated
     */
    public void setFuncName(String funcName) {
        this.funcName = funcName == null ? null : funcName.trim();
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.func_url
     *
     * @return the value of tb_functions.func_url
     *
     * @mbg.generated
     */
    public String getFuncUrl() {
        return funcUrl;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.func_url
     *
     * @param funcUrl the value for tb_functions.func_url
     *
     * @mbg.generated
     */
    public void setFuncUrl(String funcUrl) {
        this.funcUrl = funcUrl == null ? null : funcUrl.trim();
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.func_code
     *
     * @return the value of tb_functions.func_code
     *
     * @mbg.generated
     */
    public String getFuncCode() {
        return funcCode;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.func_code
     *
     * @param funcCode the value for tb_functions.func_code
     *
     * @mbg.generated
     */
    public void setFuncCode(String funcCode) {
        this.funcCode = funcCode == null ? null : funcCode.trim();
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.parent_id
     *
     * @return the value of tb_functions.parent_id
     *
     * @mbg.generated
     */
    public Integer getParentId() {
        return parentId;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.parent_id
     *
     * @param parentId the value for tb_functions.parent_id
     *
     * @mbg.generated
     */
    public void setParentId(Integer parentId) {
        this.parentId = parentId;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.func_type
     *
     * @return the value of tb_functions.func_type
     *
     * @mbg.generated
     */
    public Integer getFuncType() {
        return funcType;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.func_type
     *
     * @param funcType the value for tb_functions.func_type
     *
     * @mbg.generated
     */
    public void setFuncType(Integer funcType) {
        this.funcType = funcType;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.status
     *
     * @return the value of tb_functions.status
     *
     * @mbg.generated
     */
    public Integer getStatus() {
        return status;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.status
     *
     * @param status the value for tb_functions.status
     *
     * @mbg.generated
     */
    public void setStatus(Integer status) {
        this.status = status;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.sort_num
     *
     * @return the value of tb_functions.sort_num
     *
     * @mbg.generated
     */
    public Integer getSortNum() {
        return sortNum;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.sort_num
     *
     * @param sortNum the value for tb_functions.sort_num
     *
     * @mbg.generated
     */
    public void setSortNum(Integer sortNum) {
        this.sortNum = sortNum;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.create_time
     *
     * @return the value of tb_functions.create_time
     *
     * @mbg.generated
     */
    public Date getCreateTime() {
        return createTime;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.create_time
     *
     * @param createTime the value for tb_functions.create_time
     *
     * @mbg.generated
     */
    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column tb_functions.update_time
     *
     * @return the value of tb_functions.update_time
     *
     * @mbg.generated
     */
    public Date getUpdateTime() {
        return updateTime;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column tb_functions.update_time
     *
     * @param updateTime the value for tb_functions.update_time
     *
     * @mbg.generated
     */
    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

	@Override
	public String toString() {
		return "Function [funcId=" + funcId + ", funcName=" + funcName + ", funcUrl=" + funcUrl + ", funcCode="
				+ funcCode + ", parentId=" + parentId + ", funcType=" + funcType + ", status=" + status + ", sortNum="
				+ sortNum + ", createTime=" + createTime + ", updateTime=" + updateTime + "]";
	}
    
    
}