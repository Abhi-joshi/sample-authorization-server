package com.abhishek.sampleauthorizationserver.model;

import jakarta.persistence.*;

@Entity
@Table(name = "enduser_role")
public class EndUserRole {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "enduser_role_id")
    private long endUserRoleId;

    @Column(name = "username")
    private String username;

    @Column(name = "role")
    private String role;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "enduser_id", nullable = false)
    private EndUser endUser;

    public long getEndUserRoleId() {
        return endUserRoleId;
    }

    public void setEndUserRoleId(long endUserRoleId) {
        this.endUserRoleId = endUserRoleId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public EndUser getEndUser() {
        return endUser;
    }

    public void setEndUser(EndUser endUser) {
        this.endUser = endUser;
    }
}
