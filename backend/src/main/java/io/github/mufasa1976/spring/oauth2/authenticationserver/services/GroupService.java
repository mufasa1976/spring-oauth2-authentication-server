package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import java.util.List;

public interface GroupService {
  interface Group {
    String getName();

    String getDescription();
  }

  List<Group> getGroups();

  List<Group> getUnmappedGroups();
}
