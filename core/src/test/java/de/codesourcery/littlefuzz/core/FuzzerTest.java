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

import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FuzzerTest
{
    static class Superclass {
        Long a;
    }

    static class Subclass extends Superclass {

        static Long c;

        Long b;
    }

    private Fuzzer f;
    private Random rnd;

    @BeforeEach
    public void setup() {
        f = new Fuzzer();
        rnd = new Random();
    }

    @Test
    public void testSuperclassIsConsidered()
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.TYPE, Long.class );

        final Subclass x = new Subclass();
        f.fuzz( x, true );
        assertThat( x.a ).isNotNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    @Test
    public void testSuperclassIsConsidered2()
    {
        final Subclass x = new Subclass();
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.class);
        f.fuzz( x );
        assertThat( x.a ).isNotNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    @Test
    public void testSuperclassIsNotConsidered()
    {
        final Subclass x = new Subclass();
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextLong() ), Long.class);
        f.fuzz( x, false );
        assertThat( x.a ).isNull();
        assertThat( x.b ).isNotNull();
        assertThat( Subclass.c ).isNull();
    }

    static class Custom {
        long value;
    }

    @Test
    public void testCustomRule()
    {
        f.setTypeRule( IFuzzingRule.fromSupplier( () -> 42L ) , Long.TYPE );
        final Custom obj = f.fuzz( new Custom() );
        assertThat( obj.value ).isEqualTo( 42L );
    }

    @Test
    public void testAddTypeRuleFailsOnConflict()
    {
        f.addTypeRule( IFuzzingRule.fromSupplier( () -> 42L ), Long.TYPE );
        assertThatThrownBy( () -> f.addTypeRule( IFuzzingRule.fromSupplier( () -> 42L ), Long.TYPE )
        ).isInstanceOf( IllegalArgumentException.class );
    }

    @Test
    public void testIgnoringEqualityCheckWorks()
    {
        final Custom obj = new Custom();
        obj.value = 42L;
        f.setTypeRule( IFuzzingRule.fromSupplier( () -> 42L ) , Long.TYPE );
        f.fuzz( obj );
    }

    static class RuleTest {
        int a,b;
    }

    @Test
    public void testFieldRules()
    {
        final RuleTest obj = new RuleTest();
        f.addFieldRule( RuleTest.class, "a", IFuzzingRule.fromSupplier( () -> 42 ) );
        f.addFieldRule( RuleTest.class, "b", IFuzzingRule.fromSupplier( () -> 43 ) );

        f.fuzz( obj );
        assertThat( obj.a ).isEqualTo( 42 );
        assertThat( obj.b ).isEqualTo( 43 );
    }

    static class ClearTest {
        @SuppressWarnings("unused")
        int a;
    }

    @Test
    void testClearRules()
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextInt() ), Integer.TYPE );
        f.fuzz( new ClearTest() );
        f.clearRules();
        assertThatThrownBy( () -> f.fuzz( new ClearTest() ) ).isInstanceOf( RuntimeException.class );
    }

    @Test
    void testClearTypeRules()
    {
        f.addTypeRule( (ctx, setter) -> setter.set( rnd.nextInt() ), Integer.TYPE );
        f.fuzz( new ClearTest() );
        f.clearTypeRules();
        assertThatThrownBy( () -> f.fuzz( new ClearTest() ) ).isInstanceOf( RuntimeException.class );
    }

    static class ClearTest2 {
        @SuppressWarnings("unused")
        int a;
        @SuppressWarnings("unused")
        ClearTest b;
    }

    @Test
    void testClearFieldRules()
    {
        f.clearTypeRules();
        f.addTypeRule( (context,setter) -> setter.set( (int) context.getFieldValue() + 1), Integer.TYPE);

        f.addFieldRule( ClearTest2.class, "b", (fieldInfo, setter) -> {} );
        f.fuzz( new ClearTest2() );
        f.clearFieldRules();
        assertThatThrownBy( () -> f.fuzz( new ClearTest2() ) ).isInstanceOf( RuntimeException.class );
    }
}