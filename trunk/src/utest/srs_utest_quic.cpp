/*
The MIT License (MIT)

Copyright (c) 2013-2021 Winlin

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include <srs_utest_quic.hpp>

using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_app_quic_transport.hpp>

TEST(QuicStreamBuffer, TestWrite)
{
    SrsQuicStreamBuffer buffer(1024);
    string a(1024, 'a');
    EXPECT_EQ(1024, buffer.write(a.data(), a.size()));
}

TEST(QuicStreamBuffer, TestWriteRead)
{
    SrsQuicStreamBuffer buffer(1024);
    string a(1024, 'a');
    EXPECT_EQ(1024, buffer.write(a.data(), a.size()));

    char buf[1024];
    int nb = buffer.read(buf, sizeof(buf));
    EXPECT_EQ(1024, nb);
    string b(buf, nb);
    EXPECT_EQ(a, b);
}

TEST(QuicStreamBuffer, TestWriteReadTwoTimes)
{
    SrsQuicStreamBuffer buffer(1024);
    string a(1024, 'a');
    EXPECT_EQ(1024, buffer.write(a.data(), a.size()));

    char buf[1024];
    int nb = buffer.read(buf, 1023);
    EXPECT_EQ(1023, nb);

    nb = buffer.read(buf, 1023);
    EXPECT_EQ(1, nb);

    nb = buffer.read(buf, 1023);
    EXPECT_EQ(0, nb);
}

TEST(QuicStreamBuffer, TestWriteReadWrap)
{
    SrsQuicStreamBuffer buffer(1024);
    string a(200, 'a');
    EXPECT_EQ(200, buffer.write(a.data(), a.size()));
    EXPECT_EQ(200, buffer.size());

    char buf[1024];
    for (int i = 0; i < 1024 - 200; ++i) {
        int nb = buffer.read(buf, 100);
        EXPECT_EQ(100, nb);
        EXPECT_EQ(101, buffer.write(a.data(), 101));
        EXPECT_EQ(200 + i + 1, buffer.size());
    }

    EXPECT_EQ(0, buffer.write(a.data(), 101));
    EXPECT_EQ(1024, buffer.size());

    EXPECT_EQ(1024, buffer.read(buf, 1024));
    EXPECT_TRUE(buffer.empty());
}
