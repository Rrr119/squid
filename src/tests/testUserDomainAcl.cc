/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_AUTH

#include "auth/UserDomainAcl.h"
#include "compat/cppunit.h"
#include "ConfigParser.h"
#include "unitTestMain.h"

class TestUserDomainAcl: public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestUserDomainAcl);
    CPPUNIT_TEST(testExactPair);
    CPPUNIT_TEST(testUnknownUser);
    CPPUNIT_TEST(testWrongDomain);
    CPPUNIT_TEST(testParentDomain);
    CPPUNIT_TEST(testPlainDomainIsExact);
    CPPUNIT_TEST(testRulesStayPaired);
    CPPUNIT_TEST(testCaseSensitiveByDefault);
    CPPUNIT_TEST(testCaseInsensitiveOption);
    CPPUNIT_TEST(testWildcards);
    CPPUNIT_TEST(testMalformedPair);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testExactPair();
    void testUnknownUser();
    void testWrongDomain();
    void testParentDomain();
    void testPlainDomainIsExact();
    void testRulesStayPaired();
    void testCaseSensitiveByDefault();
    void testCaseInsensitiveOption();
    void testWildcards();
    void testMalformedPair();

private:
    static void parse(UserDomainAclData &, const char *);
};

CPPUNIT_TEST_SUITE_REGISTRATION(TestUserDomainAcl);

void
TestUserDomainAcl::parse(UserDomainAclData &data, const char *rules)
{
    char line[4096];
    snprintf(line, sizeof(line), "%s", rules);
    ConfigParser::SetCfgLine(line);
    data.parse();
    data.prepareForUse();
}

void
TestUserDomainAcl::testExactPair()
{
    UserDomainAclData data;
    parse(data, "alice example.com bob example.org");
    CPPUNIT_ASSERT_EQUAL(size_t(2), data.ruleCount());
    CPPUNIT_ASSERT(data.match("alice", "example.com"));
    CPPUNIT_ASSERT(data.match("bob", "example.org"));
}

void
TestUserDomainAcl::testUnknownUser()
{
    UserDomainAclData data;
    parse(data, "alice example.com");
    CPPUNIT_ASSERT(!data.match("mallory", "example.com"));
}

void
TestUserDomainAcl::testWrongDomain()
{
    UserDomainAclData data;
    parse(data, "alice example.com");
    CPPUNIT_ASSERT(!data.match("alice", "example.org"));
}

void
TestUserDomainAcl::testParentDomain()
{
    UserDomainAclData data;
    parse(data, "alice .example.com");
    CPPUNIT_ASSERT(data.match("alice", "example.com"));
    CPPUNIT_ASSERT(data.match("alice", "www.example.com"));
    CPPUNIT_ASSERT(!data.match("alice", "notexample.com"));
}

void
TestUserDomainAcl::testPlainDomainIsExact()
{
    UserDomainAclData data;
    parse(data, "alice example.com");
    CPPUNIT_ASSERT(data.match("alice", "example.com"));
    CPPUNIT_ASSERT(!data.match("alice", "www.example.com"));
}

void
TestUserDomainAcl::testRulesStayPaired()
{
    UserDomainAclData data;
    parse(data, "alice example.com bob example.org");
    CPPUNIT_ASSERT(!data.match("alice", "example.org"));
    CPPUNIT_ASSERT(!data.match("bob", "example.com"));
}

void
TestUserDomainAcl::testCaseSensitiveByDefault()
{
    UserDomainAclData data;
    parse(data, "Alice example.com");
    CPPUNIT_ASSERT(data.match("Alice", "example.com"));
    CPPUNIT_ASSERT(!data.match("alice", "example.com"));
}

void
TestUserDomainAcl::testCaseInsensitiveOption()
{
    UserDomainAclData data;
    parse(data, "-i Alice example.com");
    CPPUNIT_ASSERT(data.match("alice", "example.com"));
    CPPUNIT_ASSERT(data.match("ALICE", "example.com"));
}

void
TestUserDomainAcl::testWildcards()
{
    UserDomainAclData data;
    parse(data, "ANY example.com alice ANY");
    CPPUNIT_ASSERT(data.match("bob", "example.com"));
    CPPUNIT_ASSERT(data.match("alice", "any.example.org"));
    CPPUNIT_ASSERT(!data.match("bob", "example.org"));
    CPPUNIT_ASSERT(!data.match("", "example.com"));
    CPPUNIT_ASSERT(!data.match("bob", ""));
}

void
TestUserDomainAcl::testMalformedPair()
{
    UserDomainAclData data;
    parse(data, "alice example.com bob");
    CPPUNIT_ASSERT(!data.valid());
    CPPUNIT_ASSERT_EQUAL(size_t(1), data.ruleCount());
    CPPUNIT_ASSERT(!data.match("bob", "example.com"));
}

int
main(int argc, char *argv[])
{
    return TestProgram().run(argc, argv);
}

#endif /* USE_AUTH */
