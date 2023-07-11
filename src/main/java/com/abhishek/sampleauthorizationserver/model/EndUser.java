package com.abhishek.sampleauthorizationserver.model;

import jakarta.persistence.*;

import java.util.Set;

@Entity
@Table(name = "enduser")
public class EndUser {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "enduser_id")
    private long endUserId;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "email")
    private String email;

    @Column(name = "enabled")
    private Boolean enabled;

    @OneToMany(mappedBy = "endUser", fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private Set<EndUserRole> roles;

    public long getEndUserId() {
        return endUserId;
    }

    public void setEndUserId(long endUserId) {
        this.endUserId = endUserId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Set<EndUserRole> getRoles() {
        return roles;
    }

    public void setRoles(Set<EndUserRole> roles) {
        this.roles = roles;
    }
}
