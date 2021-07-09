package com.example.app;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class Token {
	private final boolean isRefresh;
	private final String value;
	private boolean isActive = true;
	private List<Token> descendants = new CopyOnWriteArrayList<>();

	public Token(boolean isRefresh, String value) {
		this.isRefresh = isRefresh;
		this.value = value;
	}

	public boolean isRefresh() {
		return isRefresh;
	}

	public String getValue() {
		return value;
	}

	public boolean isActive() {
		return isActive;
	}

	public void revoke() {
		this.isActive = false;
		for (Token descendant : descendants) {
			descendant.revoke();
		}
	}

	public void add(Token token) {
		this.descendants.add(token);
	}
}
