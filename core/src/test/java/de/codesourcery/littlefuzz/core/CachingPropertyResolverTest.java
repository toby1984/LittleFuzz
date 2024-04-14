/*
 * Copyright © 2024 Tobias Gierke (tobias.gierke@code-sourcery.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.littlefuzz.core;

import java.util.List;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CachingPropertyResolverTest
{
    private Fuzzer f;

    @BeforeEach
    void setup() {
        f = new Fuzzer();
    }

    static class TestClass
    {
        @SuppressWarnings("unused")
        int a;
    }

    @Test
    void testResolutionIsNotCached()
    {
        final IPropertyResolver r = EasyMock.createMock( IPropertyResolver.class );
        EasyMock.expect( r.getProperties( TestClass.class, true ) ).andReturn( List.of() ).times( 2 );
        EasyMock.replay( r );
        f.setPropertyResolver( r );
        f.fuzz( new TestClass() );
        f.fuzz( new TestClass() );
        EasyMock.verify( r );
    }

    @Test
    void testResolutionIsCached()
    {
        final IPropertyResolver r = EasyMock.createMock( IPropertyResolver.class );
        EasyMock.expect( r.getProperties( TestClass.class, true ) ).andReturn( List.of() );
        EasyMock.replay( r );
        f.setPropertyResolver( CachingPropertyResolver.wrap(r) );
        f.fuzz( new TestClass() );
        f.fuzz( new TestClass() );
        EasyMock.verify( r );
    }
}